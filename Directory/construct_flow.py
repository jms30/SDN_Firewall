#! usr/bin/env python

from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP,ETH_TYPE_LLDP,ETH_TYPE_MPLS,ETH_TYPE_IPV6
from ryu.ofproto.inet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP,IPPROTO_SCTP
from flow_addition import FlowAdd
import logging
class Construct():
    """
        Constructs Match object from supplied field.
        The default value of all parameters is don't-care-match-all wildcard.                 
        If no parameters are given, the returned match matches everything. 
    """
    
    def __init__(self):
        logging.info("Rule will be constructed")
        
    
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
        
        """ please check for actions that where it fits and what is its advantage """
        matchflow = FlowAdd()
        match = parser.OFPMatch()
        
        if (eth_type is not None):
            if (eth_type == ETH_TYPE_IP):
                if (ip_proto is not None):
                    
		    # For ICMP flow rules.
                    if (ip_proto == IPPROTO_ICMP):
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type, ip_proto= ip_proto, 
                                                icmpv4_type = icmpv4_type, ipv4_src = ipv4_src, ipv4_dst = ipv4_dst)
                    elif(ip_proto == IPPROTO_TCP):
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type, ip_proto= ip_proto, 
                                                ipv4_src = ipv4_src, ipv4_dst = ipv4_dst,
                                                tcp_src = tcp_src, tcp_dst = tcp_dst)
                    elif(ip_proto == IPPROTO_UDP):
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type, ip_proto= ip_proto, 
                                                ipv4_src = ipv4_src, ipv4_dst = ipv4_dst,
                                                udp_src = udp_src, udp_dst = udp_dst)
                    elif (ip_proto == IPPROTO_SCTP):
                        match = parser.OFPMatch(in_port = in_port, eth_type = eth_type, 
                                                eth_src=eth_src, eth_dst=eth_dst,
                                                ip_proto= ip_proto)
                    else:
                        # default case
                        logging.info("Please check OFPMatch--> ip_proto parameter in order to continue.")
                else:
                    logging.info("Please set OFPMatch--> ip_proto parameter in order to continue.") 
      
            elif (eth_type == ETH_TYPE_ARP):
                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,eth_src=eth_src,eth_dst=eth_dst)
            elif (eth_type == ETH_TYPE_LLDP):
                match = parser.OFPMatch(eth_type = eth_type)
            elif (eth_type == ETH_TYPE_IPV6):
                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,eth_src=eth_src,eth_dst=eth_dst)
            elif (eth_type == ETH_TYPE_MPLS):
                match = parser.OFPMatch(in_port = in_port, eth_type = eth_type,eth_src=eth_src,eth_dst=eth_dst)
        else:
            logging.info("Please set OFPMatch--> eth_type parameter in order to continue.")
        
        #Finally, add this match to flow table entry.
        if match is not None:
            matchflow.add_flow(datapath, priority, match, actions)
        else:
            logging.info("Sorry, no matching rule found or added.")
