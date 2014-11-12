#! usr/bin/env python
import logging
class TrackConnection():
    """
        Firewall Connection Tracking.
        Add seen flows to dictionary 
        and track them from incoming packets.
    """
    
    def __init__(self):
        logging.info("Firewall Connection Tracking Dictionary.")
        
    def conn_track_dict(self,dic,s_ip,d_ip,s_port,d_port,act,var):
        flag = 0
        mydict = dic
        if (var == 2):
            mydict = self.conn_track_dict(mydict, d_ip, s_ip, d_port, s_port, act, 1)
        src_ip = str(s_ip)
        list1 = [d_ip,s_port,d_port,act]
        listobj = []
        # For new flow initiators.
        if(mydict.has_key(src_ip) is False):
            key = src_ip
            tup = tuple(list1)
            listobj.append(tup)
            tup = tuple(listobj)
            mydict[key] = tup
            flag = 1
        
        # Check if same entry is found in dictionary       
        elif (mydict.has_key(src_ip) is True):
            for x in list(mydict[src_ip]):
                if (list1 == list(x)):
                    flag = 1
                    break
            
        # If unique entry, only then allow
        if(flag != 1):
            key = src_ip
            dst = mydict[key]
            dst = list(dst)
            dst.append(tuple(list1))
            tup = tuple(dst)
            mydict[key] = tup
        
        return mydict
        
