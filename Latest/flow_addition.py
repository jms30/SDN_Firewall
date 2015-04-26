#! usr/bin/env python
import logging
class FlowAdd():
    """ 
        Default Function for constructing instructions.
        Sends constructed message to connected Switch.
    """

    def __init__ (self):
        logging.info("Flow Table rules are sent to switch")

   
    def add_flow(self,datapath, priority, match, actions, idle_timeout=1800):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)
        