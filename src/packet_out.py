#! usr/bin/env python
import logging
class SendPacket():
    
    def __init__(self):
        logging.info("Controller is configured to handle packets coming from switch.")
        
    def send(self,datapath, msg, port, action):
        data = None
        parser = datapath.ofproto_parser
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=port, actions=action, data=data)
        datapath.send_msg(out)