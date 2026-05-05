from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet, arp, ipv4
from os_ken.ofproto import ofproto_v1_3

try:
    from controllers.task4.network_awareness import NetworkAwareness
except ImportError:
    from network_awareness import NetworkAwareness


ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ETH_TYPE_LLDP = 0x88cc
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806


class FaultTolerantForward(app_manager.OSKenApp):
    """
    Task 4 controller: fault-tolerant minimum-delay forwarding.

    Based on Task 3:
    1. Uses NetworkAwareness to measure link delay.
    2. Computes the minimum-delay path.
    3. Installs bidirectional IPv4 flow entries.
    4. Handles ARP broadcast loop.
    5. When link status changes, deletes old flow entries.
       Then the next PacketIn triggers route recalculation.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "network_awareness": NetworkAwareness
    }

    def __init__(self, *args, **kwargs):
        super(FaultTolerantForward, self).__init__(*args, **kwargs)

        self.network_awareness = kwargs["network_awareness"]

        # Task 4 still uses minimum-delay path.
        self.weight = "delay"

        # dpid -> {mac: port}
        self.mac_to_port = {}

        # ARP broadcast loop suppression:
        # (dpid, src_mac, dst_ip) -> in_port
        self.arp_history = {}

        self.logger.info(">>> FaultTolerantForward started")

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
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
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    def delete_flow(self, datapath, match):
        """
        Delete flow entries matching the given match field.

        In Task 4, this is used after link down/up events.
        Once old IPv4/ARP flow entries are removed, packets will hit
        the table-miss entry again and be sent to the controller.
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match
        )

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install table-miss flow entry.
        Unmatched packets are sent to the controller.
        """
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return

        # LLDP is used by OS-Ken topology discovery.
        # It must not be handled as normal traffic.
        if eth_pkt.ethertype == ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt is not None:
            self.handle_arp(msg, in_port, eth_pkt, arp_pkt)
            return

        if ipv4_pkt is not None:
            self.handle_ipv4(msg, eth_pkt, ipv4_pkt)
            return

    def handle_arp(self, msg, in_port, eth_pkt, arp_pkt):
        """
        ARP handling:
        1. Learn source MAC address.
        2. Suppress duplicated broadcast ARP requests in loop topology.
        3. Forward ARP packet.
        """
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        self.mac_to_port.setdefault(dpid, {})

        drop = False

        if dst_mac == ETHERNET_MULTICAST:
            dst_ip = arp_pkt.dst_ip
            arp_key = (dpid, src_mac, dst_ip)

            if arp_key in self.arp_history:
                if self.arp_history[arp_key] != in_port:
                    drop = True
            else:
                self.arp_history[arp_key] = in_port

        if drop:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=[],
                data=None
            )
            datapath.send_msg(out)
            return

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ETH_TYPE_ARP,
                eth_dst=dst_mac
            )
            self.add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions,
                idle_timeout=5,
                hard_timeout=10
            )

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    def handle_ipv4(self, msg, eth_pkt, ipv4_pkt):
        """
        Compute the minimum-delay path and install bidirectional flows.
        """
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        dpid_path = self.network_awareness.shortest_path(
            src_ip,
            dst_ip,
            weight=self.weight
        )

        if not dpid_path:
            return

        if len(dpid_path) < 3:
            return

        port_path = []

        try:
            for i in range(1, len(dpid_path) - 1):
                current_node = dpid_path[i]
                previous_node = dpid_path[i - 1]
                next_node = dpid_path[i + 1]

                in_port = self.network_awareness.link_info[
                    (current_node, previous_node)
                ]
                out_port = self.network_awareness.link_info[
                    (current_node, next_node)
                ]

                port_path.append((in_port, current_node, out_port))

        except KeyError:
            self.logger.info("port info not ready")
            return

        self.show_path(src_ip, dst_ip, dpid_path, port_path)

        for in_port, dpid, out_port in port_path:
            self.send_ipv4_flow_mod(
                dpid=dpid,
                src_ip=src_ip,
                dst_ip=dst_ip,
                in_port=in_port,
                out_port=out_port
            )

            self.send_ipv4_flow_mod(
                dpid=dpid,
                src_ip=dst_ip,
                dst_ip=src_ip,
                in_port=out_port,
                out_port=in_port
            )

        first_in_port, first_dpid, first_out_port = port_path[0]
        datapath = self.network_awareness.switch_info.get(first_dpid)

        if datapath is None:
            return

        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        actions = [parser.OFPActionOutput(first_out_port)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=first_in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    def send_ipv4_flow_mod(self, dpid, src_ip, dst_ip, in_port, out_port):
        datapath = self.network_awareness.switch_info.get(dpid)

        if datapath is None:
            return

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ETH_TYPE_IPV4,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )

        actions = [parser.OFPActionOutput(out_port)]

        self.add_flow(
            datapath=datapath,
            priority=1,
            match=match,
            actions=actions,
            idle_timeout=10,
            hard_timeout=30
        )

    def show_path(self, src_ip, dst_ip, dpid_path, port_path):
        total_delay = self.network_awareness.get_path_delay(dpid_path)

        self.logger.info("path: %s -> %s", src_ip, dst_ip)

        path_str = src_ip + " -> "
        for in_port, dpid, out_port in port_path:
            path_str += "{}:s{}:{} -> ".format(in_port, dpid, out_port)
        path_str += dst_ip

        self.logger.info(path_str)
        self.logger.info(
            "delay: %.6f s, estimated RTT: %.6f s",
            total_delay,
            total_delay * 2
        )

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def fault_tolerant_handler(self, ev):
        """
        Core of Task 4.

        When a port status changes, the old path may no longer be valid.
        Therefore, all ARP/IPv4 forwarding entries installed by this app
        are deleted. The next packet will be sent to the controller again,
        and a new minimum-delay path will be calculated.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto

        reason_map = {
            ofp.OFPPR_ADD: "ADD",
            ofp.OFPPR_DELETE: "DELETE",
            ofp.OFPPR_MODIFY: "MODIFY"
        }

        reason = reason_map.get(msg.reason, "UNKNOWN")

        self.logger.info(
            ">>> port status changed: dpid=%s port=%s reason=%s",
            datapath.id,
            msg.desc.port_no,
            reason
        )

        for dp in list(self.network_awareness.switch_info.values()):
            parser = dp.ofproto_parser

            match_ipv4 = parser.OFPMatch(eth_type=ETH_TYPE_IPV4)
            match_arp = parser.OFPMatch(eth_type=ETH_TYPE_ARP)

            self.delete_flow(dp, match_ipv4)
            self.delete_flow(dp, match_arp)

        self.mac_to_port.clear()
        self.arp_history.clear()

        self.network_awareness.topo_map.clear()
        self.network_awareness.link_info.clear()
        self.network_awareness.lldp_delay.clear()

        self.logger.info(
            ">>> old flows cleared; wait for topology refresh and new PacketIn"
        )
