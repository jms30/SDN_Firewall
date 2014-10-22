		#! usr/bin/env python
import copy

class parse_firewall:
    
    
    def parse(self):
        firewall_file = open("firewall.txt")
        list1 = []
        firewall_dict = {}
        listobj = []
        #print f.readlines() 
        
        
        
        lines = [line.strip() for line in firewall_file]
        #print lines
        for i in range(len(lines)):
            
            #print "\n each firewall rule: ",lines[i]
            
            list1.append(lines[i].split(',')) 
            #print "yourlist is splitting each firewall rule and adding to the list",yourlist
            list2 = copy.deepcopy(list1)
            #print "\n mylist a copy of your list:", mylist
            if(firewall_dict.has_key(str(list2[i][0])) is False):
                #print "no entry is found so we will add this in dictionary"
                
                key = str(list2[i][0])
                #print "key is :",xyz
                list2[i].remove(key)
                tup = tuple(list2[i])
                
                listobj.append(tup)
                tup = tuple(listobj)
                
                firewall_dict[key] = tup
                #print firewall_dict
                
            elif (firewall_dict.has_key(str(list2[i][0])) is True):
                #print "entry is found so we append this firewall rule for this source address"
                key = str(list2[i][0])
                dst = firewall_dict[key]
                dst = list(dst)
                
                #print "abc        / ",abc
                #print "key is :",xyz
                list2[i].remove(key)
                dst.append(tuple(list2[i]))
                tup = tuple(dst)
                firewall_dict[key] = tup
                
                #print firewall_dict
         
            del listobj[:] 
        print len(firewall_dict.keys())
        return firewall_dict

