from os_ken.base import app_manager
from os_ken.base.app_manager import lookup_service_brick
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3
from os_ken.topology.switches import LLDPPacket

import networkx as nx
import time


GET_TOPOLOGY_INTERVAL = 2
SEND_ECHO_REQUEST_INTERVAL = 0.05
GET_DELAY_INTERVAL = 2

UNKNOWN_DELAY = 999.0


class NetworkAwareness(app_manager.OSKenApp):
    """
    Network awareness module for Task 3.

    This version does NOT depend on get_switch/get_link/get_host,
    because those API requests may return empty results under the custom run_osken.py runner.

    Instead, it directly reads the OS-Ken topology service:
        lookup_service_brick("switches")

    It maintains:
        switch_info: dpid -> datapath
        link_info: (node1, node2) -> output port on node1
        topo_map: weighted graph
        echo_delay: dpid -> controller-switch RTT
        lldp_delay: (src_dpid, dst_dpid) -> LLDP delay
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)

        self.switch_info = {}
        self.link_info = {}
        self.port_info = {}
        self.topo_map = nx.Graph()

        self.echo_delay = {}
        self.lldp_delay = {}

        self.switches = None

        self.logger.info(">>> NetworkAwareness started")

        self.topo_thread = hub.spawn(self._get_topology)
        self.delay_thread = hub.spawn(self._delay_monitor)

    def add_flow(self, datapath, priority, match, actions):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofp.OFPP_CONTROLLER,
                ofp.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if datapath is None or datapath.id is None:
            return

        dpid = datapath.id

        if ev.state == MAIN_DISPATCHER:
            self.switch_info[dpid] = datapath
            self.logger.info(">>> switch connected: dpid=%s", dpid)

        elif ev.state == DEAD_DISPATCHER:
            self.switch_info.pop(dpid, None)
            self.logger.info(">>> switch disconnected: dpid=%s", dpid)

    def _get_switches_service(self):
        if self.switches is None:
            self.switches = lookup_service_brick("switches")

        return self.switches

    def _get_topology(self):
        """
        Periodically rebuild topology by directly reading switches service.
        """
        hub.sleep(3)

        while True:
            try:
                switches_service = self._get_switches_service()

                if switches_service is None:
                    self.logger.info(">>> switches service not ready")
                    hub.sleep(GET_TOPOLOGY_INTERVAL)
                    continue

                self._rebuild_topology_from_switches_service(switches_service)

            except Exception as e:
                self.logger.info(">>> topology scan error: %s", e)

            hub.sleep(GET_TOPOLOGY_INTERVAL)

    def _rebuild_topology_from_switches_service(self, switches_service):
        new_graph = nx.Graph()
        new_link_info = {}
        new_port_info = {}

        # 1. Read switches.
        dps = getattr(switches_service, "dps", {})
        for dpid, datapath in dps.items():
            new_port_info.setdefault(dpid, set())
            self.switch_info[dpid] = datapath

            port_state = switches_service.port_state.get(dpid, {})
            for port_no in port_state.keys():
                new_port_info[dpid].add(port_no)

        # 2. Read switch-switch links.
        links = list(getattr(switches_service, "links", {}).keys())

        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no

            new_port_info.setdefault(src_dpid, set()).discard(src_port)
            new_port_info.setdefault(dst_dpid, set()).discard(dst_port)

            new_link_info[(src_dpid, dst_dpid)] = src_port
            new_link_info[(dst_dpid, src_dpid)] = dst_port

            old_delay = UNKNOWN_DELAY
            if self.topo_map.has_edge(src_dpid, dst_dpid):
                old_delay = self.topo_map[src_dpid][dst_dpid].get("delay", UNKNOWN_DELAY)

            new_graph.add_edge(
                src_dpid,
                dst_dpid,
                hop=1,
                delay=old_delay,
                is_host=False
            )

        # 3. Read hosts discovered by switches service.
        hosts_state = getattr(switches_service, "hosts", {})
        hosts = list(hosts_state.values())

        host_count = 0

        for host in hosts:
            if not host.ipv4:
                continue

            host_ip = host.ipv4[0]
            sw_dpid = host.port.dpid
            sw_port = host.port.port_no

            new_link_info[(sw_dpid, host_ip)] = sw_port
            new_link_info[(host_ip, sw_dpid)] = 0

            new_graph.add_edge(
                host_ip,
                sw_dpid,
                hop=1,
                delay=0,
                is_host=True
            )

            host_count += 1

        self.topo_map = new_graph
        self.link_info = new_link_info
        self.port_info = new_port_info

        self.logger.info(
            ">>> topology scan: switches=%d, links=%d, hosts=%d, nodes=%d, edges=%d",
            len(dps),
            len(links),
            host_count,
            self.topo_map.number_of_nodes(),
            self.topo_map.number_of_edges()
        )

    def shortest_path(self, src, dst, weight="delay"):
        try:
            if src not in self.topo_map or dst not in self.topo_map:
                self.logger.info(
                    "host not find/no path: src=%s in_graph=%s, dst=%s in_graph=%s",
                    src,
                    src in self.topo_map,
                    dst,
                    dst in self.topo_map
                )
                return None

            path = nx.shortest_path(self.topo_map, src, dst, weight=weight)
            return path

        except Exception as e:
            self.logger.info("host not find/no path: %s", e)
            return None

    def get_path_delay(self, path):
        if not path or len(path) < 2:
            return 0

        total_delay = 0

        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]

            if self.topo_map.has_edge(src, dst):
                total_delay += self.topo_map[src][dst].get("delay", 0)

        return total_delay

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def lldp_packet_in_handler(self, ev):
        """
        Read LLDP delay from modified os_ken.topology.switches.PortData.delay.
        """
        msg = ev.msg
        dpid = msg.datapath.id

        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)

            switches_service = self._get_switches_service()
            if switches_service is None:
                return

            for port in switches_service.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    self.lldp_delay[(src_dpid, dpid)] = switches_service.ports[port].delay
                    return

        except Exception:
            return

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id

        try:
            send_time = float(msg.data.decode("utf-8"))
            rtt = time.time() - send_time
            self.echo_delay[dpid] = rtt

        except Exception:
            return

    def _delay_monitor(self):
        hub.sleep(5)

        while True:
            try:
                self._send_all_echo_requests()
                self._update_all_delays()
            except Exception as e:
                self.logger.info(">>> delay monitor error: %s", e)

            hub.sleep(GET_DELAY_INTERVAL)

    def _send_all_echo_requests(self):
        for datapath in list(self.switch_info.values()):
            parser = datapath.ofproto_parser
            timestamp = time.time()
            data = f"{timestamp:.10f}".encode("utf-8")

            echo_req = parser.OFPEchoRequest(datapath, data=data)
            datapath.send_msg(echo_req)

            hub.sleep(SEND_ECHO_REQUEST_INTERVAL)

    def _update_all_delays(self):
        updated = 0

        for src, dst in list(self.topo_map.edges):
            if self.topo_map[src][dst].get("is_host", False):
                continue

            try:
                lldp_delay_s12 = self.lldp_delay[(src, dst)]
                lldp_delay_s21 = self.lldp_delay[(dst, src)]
                echo_delay_s1 = self.echo_delay[src]
                echo_delay_s2 = self.echo_delay[dst]

                delay = (
                    lldp_delay_s12 +
                    lldp_delay_s21 -
                    echo_delay_s1 -
                    echo_delay_s2
                ) / 2.0

                if delay < 0:
                    delay = 0

                self.topo_map[src][dst]["delay"] = delay
                updated += 1

            except Exception:
                continue

        if updated > 0:
            self.logger.info(">>> delay updated: %d switch-links", updated)
