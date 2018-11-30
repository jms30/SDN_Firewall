#! usr/bin/env python
import logging
from reset_flow_table import ResetSwitch
class SwitchInfo():
    """
        This class handles switch connection and 
        disconnection information. Set the RYU Event 
        object and make the most out of it.
    """
    
    
    def __init__(self,event):
        switch = event.dp
        if event.enter:
            logging.info('datapath has joined')
            logging.info(switch.ofproto)
            logging.info(switch.ofproto_parser)
            self.__switch_connected(switch)
        else:
            self.__switch_disconnected(switch)
           
    def __switch_connected(self, sw):
        
        logging.info("Switch %s has connected with OFP 1.3...",sw.id)
        ResetSwitch(sw)
   
    def __switch_disconnected(self, sw):
        logging.info("Switch %s has disconnected from OFP 1.3...",sw.id)
    