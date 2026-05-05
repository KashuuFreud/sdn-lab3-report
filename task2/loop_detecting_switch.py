from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import arp
from os_ken.lib.packet import ether_types
from os_ken import log


ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"


class Switch_Dict(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch_Dict, self).__init__(*args, **kwargs)

        # Task 1: self-learning MAC table
        # dpid -> {mac: port}
        self.mac_to_port = {}

        # Task 2: ARP broadcast loop detection table
        # (dpid, src_mac, dst_ip) -> in_port
        self.sw = {}

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst
        )

        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss flow entry:
        # unmatched packets are sent to the controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofp.OFPP_CONTROLLER,
                ofp.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return

        # Ignore LLDP packets
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Ignore IPv6 packets to reduce unnecessary flooding
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dst = eth_pkt.dst
        src = eth_pkt.src

        self.logger.info(
            "packet in: dpid=%s src=%s dst=%s in_port=%s",
            dpid, src, dst, in_port
        )

        self.mac_to_port.setdefault(dpid, {})

        arp_pkt = pkt.get_protocol(arp.arp)

        # ------------------------------------------------------------
        # Task 2: detect and drop duplicated ARP broadcast in loop
        # ------------------------------------------------------------
        if dst == ETHERNET_MULTICAST and arp_pkt is not None:
            arp_key = (dpid, src, arp_pkt.dst_ip)

            if arp_key in self.sw:
                # Same ARP request enters the same switch from another port.
                # It is considered as a duplicated broadcast caused by loop.
                if self.sw[arp_key] != in_port:
                    self.logger.info(
                        "drop duplicated ARP: dpid=%s src=%s dst_ip=%s old_port=%s new_port=%s",
                        dpid, src, arp_pkt.dst_ip, self.sw[arp_key], in_port
                    )

                    out = parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=msg.buffer_id,
                        in_port=in_port,
                        actions=[],
                        data=None
                    )

                    dp.send_msg(out)
                    return
            else:
                # First time seeing this ARP request on this switch
                self.sw[arp_key] = in_port

        # ------------------------------------------------------------
        # Task 1: self-learning switch
        # ------------------------------------------------------------

        # Learn source MAC address
        self.mac_to_port[dpid][src] = in_port

        # Decide output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        # Install flow entry when destination port is known
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst,
                eth_type=eth_pkt.ethertype
            )

            self.add_flow(
                datapath=dp,
                priority=1,
                match=match,
                actions=actions,
                idle_timeout=0,
                hard_timeout=5
            )

        # Send current packet out
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        dp.send_msg(out)


if __name__ == "__main__":
    log.init_log()
    app_manager.AppManager.run_apps([
        "controllers.task2.loop_detecting_switch"
    ])
