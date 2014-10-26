SDN_Firewall
============

SDN Firewall Project is about implementation of Firewall on SDN Controller by running bunch of Controller Application.

This repository consists of few RYU Applications which are just python scripts written for running firewall functionality on RYU controller. 

There are 3 types of Firewall application each of which having 2 version. They are capable of tracking a connection between 2 communicating parties. Namely,
Inefficient Firewall
Insecure Firewall
Secure Firewall

1) Inefficient Firewall:
It is named inefficient because it is not using Flow Tables extensively to store any flow table entries. It simply makes switch to forward everything to the controller. And on controller, Upon receiving each packet, it checks it with firewall rules. 

2) Insecure Firewall:
This application uses Flow tables to store flow table entries on switch so that next time packets from that flow won't be forwarded to the controller. That creates vulnerability in the system. Suppose if the firewall rule says that A can communicate to B but B can not initiate TCP connection. If A starts communication and since Firewall Rule allows this, controller will add two way rules on OVS. Even though connection terminates, The flow table entries still exists. Hence, gives B chance to initiate communication with A. Since 2 way Flow table rules are added, this application is most efficient in terms of packet exchange. 

3) Secure Firewall:
Here, upon matching firewall rule, we are adding only 1 way flow table enties. This makes packets from other communication party to be seen by controller. Hence, controller can take a look back in firewall rules and can make up a decision of forwarding or dropping. Hence, This is the most secure case and efficient than 1st application.


