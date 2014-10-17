# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet,ethernet,ipv4, udp, tcp
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP, ETH_TYPE_LLDP,ETH_TYPE_IPV6, ETH_TYPE_MPLS
from ryu.ofproto.inet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP,IPPROTO_SCTP
from parse_firewall_rules import parse_firewall


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    inner_policy = {}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        parser = parse_firewall()
        self.inner_policy = parser.parse()
        self.logger.info("dict is ready")


    """
        Called whenever a switch connects.                        
        Verifies that switch runs OpenFlow 1.3.
        Initialized switch.
        Paramteres: sw - the switch
    """
    def __switch_connected(self, sw):
        self.logger.info("switch %s connected",sw.id)
        self.__reset_switch(sw)
   
    
    """
        Called whenever a switch disconnects.
        Parameters: sw - the switch
    """
    def __switch_disconnected(self, sw):
        self.logger.info("switch %s disconnected",sw.id)
    
    
    """
         An event class handler to notify 
         connection/disconnection of a switch.
    """ 
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        datapath = ev.dp
        if ev.enter:
            self.logger.info('datapath has joined')
            self.logger.info(datapath.ofproto)
            self.logger.info(datapath.ofproto_parser)
            self.__switch_connected(datapath)
        else:
            self.logger.info('datapath has left')
            self.__switch_disconnected(datapath)   
            

    """
        Reset the switch. 
        Flush all flow table entries.
        set up default behavior
    """  
    def __reset_switch(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath,0,0,0,
                                                      ofproto.OFPFC_DELETE,
                                                      0,0,1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY,
                                                      )
        self.logger.info("deleting all flow table entries in the tables :" ) 
        datapath.send_msg(flow_mod)
        
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly. 
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath = datapath,actions = actions, priority=0)
        actions = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        self.add_flow(datapath = datapath,actions = actions, priority=10000, eth_type=ETH_TYPE_LLDP)
        
    
    """ 
        Default Function for constructing instructions.
        Sends constructed message to connected Switch.
    """        
    def __add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=1800)
        datapath.send_msg(mod)
        
        
    """
        Constructs Match object from supplied field.
        The default value of all parameters is don't-care-match-all wildcard.                 
        If no parameters are given, the returned match matches everything. 
    """
    def add_flow(self,datapath,actions, priority = 1000 ,in_port=None, in_phy_port=None, metadata=None, eth_dst=None, eth_src=None, eth_type=None,
             vlan_vid=None, vlan_pcp=None, ip_dscp=None, ip_ecn=None, ip_proto=None, ipv4_src=None, ipv4_dst=None,
             tcp_src=None, tcp_dst=None, udp_src=None, udp_dst=None, sctp_src=None, sctp_dst=None, icmpv4_type=None,
             icmpv4_code=None, arp_op=None, arp_spa=None, arp_tpa=None, arp_sha=None, arp_tha=None,
             ipv6_src=None, ipv6_dst=None, ipv6_flabel=None, icmpv6_type=None, icmpv6_code=None,
             ipv6_nd_target=None, ipv6_nd_sll=None, ipv6_nd_tll=None, mpls_label=None, mpls_tc=None, mpls_bos=None,
             pbb_isid=None, tunnel_id=None, ipv6_exthdr=None):
        
        assert (datapath is not None),"Datapath Object is Not set. "
        assert (actions is not None),"Actions Object is Not set. "
        
        parser = datapath.ofproto_parser
        
        """ please check for actions that where it fits and what is it's advantage """
        
        match = parser.OFPMatch()
        
        if (eth_type is not None):
            self.logger.info("Eth_Type is set")
            if (eth_type == ETH_TYPE_IP):
                self.logger.info("IP Object is set")
                if (ip_proto is not None):
                    self.logger.info("IP_Proto is set" )
                    if (ip_proto == IPPROTO_ICMP):
                        self.logger.info("ICMP object type is set")
                        if (ipv4_src is not None)  and  (ipv4_dst is not None): 
                            if(icmpv4_type is not None)  and  (icmpv4_code is not None):
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, icmpv4_type = icmpv4_type, icmpv4_code = icmpv4_code, 
                                                        ipv4_src = ipv4_src, ipv4_dst= ipv4_dst)
                            elif (icmpv4_code is not None):
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, icmpv4_code = icmpv4_code, 
                                                        ipv4_src = ipv4_src, ipv4_dst= ipv4_dst)
                            elif (icmpv4_type is not None):
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, icmpv4_type = icmpv4_type, 
                                                        ipv4_src = ipv4_src, ipv4_dst= ipv4_dst)
                            else:
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, ipv4_src = ipv4_src, ipv4_dst= ipv4_dst)
                        else:
                            if(icmpv4_type is not None)  and  (icmpv4_code is not None):
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, icmpv4_type = icmpv4_type, icmpv4_code = icmpv4_code)
                            elif (icmpv4_code is not None):
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, icmpv4_code = icmpv4_code)
                            elif (icmpv4_type is not None):
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto, icmpv4_type = icmpv4_type)
                            else:
                                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                        eth_src=eth_src,eth_dst=eth_dst, 
                                                        ip_proto= ip_proto)
                    elif(ip_proto == IPPROTO_TCP):
                        self.logger.info("TCP object is set")
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                ip_proto= ip_proto, ipv4_src = ipv4_src, ipv4_dst = ipv4_dst,
                                                tcp_src= tcp_src, tcp_dst = tcp_dst)
                    elif(ip_proto == IPPROTO_UDP):
                        self.logger.info("UDP object is set")
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,
                                                ip_proto= ip_proto, ipv4_src = ipv4_src, ipv4_dst = ipv4_dst,
                                                udp_src= udp_src, udp_dst = udp_dst)
                    elif (ip_proto == IPPROTO_SCTP):
                        self.logger.info("SCTP object is set")
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type, 
                                                eth_src=eth_src, eth_dst=eth_dst,
                                                ip_proto= ip_proto)
                    else:
                        # default case
                        self.logger.info("Please check OFPMatch--> ip_proto parameter in order to continue.")
                else:
                    self.logger.info("Please set OFPMatch--> ip_proto parameter in order to continue.")       
            elif (eth_type == ETH_TYPE_ARP):
                self.logger.info("ARP object is set")
                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,eth_src=eth_src,eth_dst=eth_dst)
            elif (eth_type == ETH_TYPE_LLDP):
                self.logger.info("LLDP rule will be added")
                match = parser.OFPMatch(eth_type = eth_type)
            elif (eth_type == ETH_TYPE_IPV6):
                self.logger.info("IPv6 object is set")
                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,eth_src=eth_src,eth_dst=eth_dst)
            elif (eth_type == ETH_TYPE_MPLS):
                self.logger.info("MPLS object is set")
                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,eth_src=eth_src,eth_dst=eth_dst)
        else:
            self.logger.info("Please set OFPMatch--> eth_type parameter in order to continue.")

        #Finally, add this match to flow table entry.
        if match is not None:
            self.__add_flow(datapath, priority, match, actions)
        else:
            self.logger.info("Sorry, no matching rule found or added.")
        

    """
        Handle firewall rules to incoming packets.
        Decode packets, and check for suitable Firewall Rules.
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        try:
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src
            ethtype = eth.ethertype
            dpid = datapath.id
            
            # We have hardcoded this for security purpose of the project.
            self.mac_to_port.setdefault(dpid, {'90:e2:ba:1c:55:54':1 , '90:e2:ba:1c:55:55':2})
    
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
    
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            
            if (ethtype == ETH_TYPE_IP)  or  (ethtype == ETH_TYPE_ARP):
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
            
            action_fwd_to_out_port = [parser.OFPActionOutput(out_port)]
            actions_default =  action_fwd_to_out_port
            action_fwd_to_in_port  = [parser.OFPActionOutput(in_port)]
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
    
            if(out_port != ofproto.OFPP_FLOOD) and (ethtype == ETH_TYPE_IP):
                ipo = pkt.get_protocols(ipv4.ipv4)[0]
                
                #Check for ICMP
                if(ipo.proto == IPPROTO_ICMP):
                    if (self.inner_policy.has_key(ipo.src)):
                        for i in range(0,len(self.inner_policy.get(ipo.src))):
                            if self.inner_policy.get(ipo.src)[i][0] == ipo.dst:
                                xyz = self.inner_policy.get(ipo.src)[i]
                                if(xyz[1]=='ICMP'):
                                    if (xyz[5] == 'ALLOW'):
                                        actions_default = action_fwd_to_out_port
                                        break
                                    else:
                                        actions_default = action_drop
                                else:
                                    actions_default = action_drop
                            else:
                                actions_default = action_drop
                    else:
                        actions_default = action_drop
                
                
                elif (ipo.proto == IPPROTO_TCP):
                    tcpo = pkt.get_protocol(tcp.tcp)
                
                #Check for TCP SYN ONLY.
                    if (tcpo.bits == 2):
                        flag1 = 0
                        if self.inner_policy.has_key(ipo.src):
                            for i in range(0,len(self.inner_policy.get(ipo.src))):
                                if self.inner_policy.get(ipo.src)[i][0] == ipo.dst:
                                    xyz = self.inner_policy.get(ipo.src)[i]
                                    if((xyz[1]=='TCP') and (int(xyz[2]) == tcpo.src_port) and (int(xyz[3]) == tcpo.dst_port) and (xyz[4] == 'NEW')  and  (xyz[5] == 'ALLOW')):
                                        flag1 = 1
                                        actions_default = action_fwd_to_out_port
                                        self.add_flow(datapath=datapath, actions=actions_default, priority=1001, in_port=in_port, 
                                                      eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_TCP, 
                                                      ipv4_src = ipo.src, ipv4_dst = ipo.dst, 
                                                      tcp_src = tcpo.src_port, tcp_dst = tcpo.dst_port)
                                        
                                        self.add_flow(datapath=datapath, actions=action_fwd_to_in_port, priority=1000, in_port=out_port, 
                                                      eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_TCP, 
                                                      ipv4_src = ipo.dst, ipv4_dst= ipo.src,
                                                      tcp_src = tcpo.dst_port, tcp_dst = tcpo.src_port)
                                        break
                                    else:
                                        actions_default = action_drop
                                else:
                                    actions_default = action_drop
                        if(flag1 == 0):
                            self.add_flow(datapath=datapath, actions=actions_default, priority=1000, in_port=in_port, 
                                          eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_TCP, 
                                          ipv4_src = ipo.src, ipv4_dst = ipo.dst, 
                                          tcp_src = tcpo.src_port, tcp_dst = tcpo.dst_port)
                    # for all remaining packets, DROP
                    else:
                        self.add_flow(datapath=datapath, actions=actions_default, priority=1001, in_port=in_port, 
                                      eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_TCP, 
                                      ipv4_src = ipo.src, ipv4_dst= ipo.dst, 
                                      tcp_src = tcpo.src_port,tcp_dst = tcpo.dst_port)
                    
                elif (ipo.proto == IPPROTO_UDP):
                    udpo = pkt.get_protocol(udp.udp)
                    flag2 = 0
                    if self.inner_policy.has_key(ipo.src):
                        for i in range(0,len(self.inner_policy.get(ipo.src))):
                            if self.inner_policy.get(ipo.src)[i][0] == ipo.dst:
                                xyz = self.inner_policy.get(ipo.src)[i]
                                if((xyz[1]=='UDP') and (int(xyz[2]) == udpo.src_port) and (int(xyz[3]) == udpo.dst_port) and (xyz[5] == 'ALLOW')):
                                    flag2 = 1
                                    actions_default = action_fwd_to_out_port
                                    self.add_flow(datapath=datapath, actions=actions_default, priority=1001, in_port=in_port, 
                                                  eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_UDP, 
                                                  ipv4_src = ipo.src, ipv4_dst = ipo.dst, 
                                                  udp_src = udpo.src_port, udp_dst = udpo.dst_port)
                                    
                                    self.add_flow(datapath=datapath, actions=actions_default, priority=1000, in_port=in_port, 
                                                  eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_UDP, 
                                                  ipv4_src = ipo.dst, ipv4_dst = ipo.src, 
                                                  udp_src = udpo.dst_port, udp_dst = udpo.src_port)
                                    break
                                else:
                                    actions_default = action_drop
                            else:
                                actions_default = action_drop
                    if(flag2 == 0):
                        self.add_flow(datapath=datapath, actions=actions_default, priority=1000, in_port=in_port, 
                                      eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_UDP, 
                                      ipv4_src = ipo.src, ipv4_dst = ipo.dst, 
                                      udp_src = udpo.src_port, udp_dst = udpo.dst_port)
                        
                else:
                    self.logger.info("Wrong IP protocol found")
                    actions_default = action_drop
            
            # Handling ARP Rules.
            elif(out_port != ofproto.OFPP_FLOOD)  and  (ethtype == ETH_TYPE_ARP):
                self.add_flow(datapath=datapath, actions=action_fwd_to_out_port, priority=1000, in_port = in_port, 
                              eth_type= ETH_TYPE_ARP, eth_src= src, eth_dst = dst)
                actions_default = action_fwd_to_out_port
                
        except Exception as err:
            self.logger.info("MYERROR:")
            self.logger.info(err.message)
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
            actions_default = action_drop
            
        finally:    
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
    
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions_default, data=data)
            datapath.send_msg(out)

