#! usr/bin/env python
import logging
from ryu.ofproto.ether import ETH_TYPE_LLDP
from construct_flow import Construct

class ResetSwitch():
    """
        Reset the switch. 
        Flush all flow table entries.
        set up default behavior
    """
    
    def __init__(self,dp):
        
        self.__reset_switch(dp)
        
      
    def __reset_switch(self,dp):
        assert (dp is not None),"Datapath Object is Not set. "
        
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = dp.ofproto_parser.OFPFlowMod(dp,0,0,0,
                                                ofproto.OFPFC_DELETE,
                                                0,0,1,
                                                ofproto.OFPCML_NO_BUFFER,
                                                ofproto.OFPP_ANY,
                                                ofproto.OFPG_ANY,
                                                )
        logging.info("Deleting all Flow Table entries..." )
        dp.send_msg(flow_mod)
        
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly. 
        
        const = Construct()
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        const.add_flow(datapath = dp, actions = actions, priority=0)
        
        actions = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        const.add_flow(datapath = dp, actions = actions, priority=10000, eth_type=ETH_TYPE_LLDP)
