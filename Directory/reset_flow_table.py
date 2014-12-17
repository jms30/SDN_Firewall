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
        logging.info("deleting all flow table entries in the tables :" )
        dp.send_msg(flow_mod)
        
        const = Construct()
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        const.add_flow(datapath = dp, actions = actions, priority=0)
        
        actions = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        const.add_flow(datapath = dp, actions = actions, priority=10000, eth_type=ETH_TYPE_LLDP)
