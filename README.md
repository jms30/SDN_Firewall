SDN_Firewall
============

SDN Firewall Project is about implementation of Firewall on SDN Controller by running bunch of Controller Application.

This repository consists of few RYU Applications which are just python scripts written for running firewall functionality on RYU controller. 

There are 2 types of Firewall application each of which having 2 version. They are capable of tracking a connection between 2 communicating parties. Namely,
Inefficient Firewall
Efficient Firewall

1) Inefficient Firewall:
It is named inefficient because it is not using Flow Tables extensively to store any flow table entries. It simply makes switch to forward everything to the controller. And on controller, upon receiving each packet, it checks it with firewall rules. 

2) Insecure Firewall:
This application uses Flow tables to store flow table entries on switch so that next time packets from that flow won't be forwarded to the controller. Hence, compared to previous case, this files are efficient in terms of packet exchange.

Stateful and Stateless firewalls can also be implemented on SDN Controller. 

1) Stateful firewall:
In this type of firewall, we keep the states of the seen packets. These states are maintained in order to detect the flow of the packet exchange. So that next time when a packet is received by the controller, controller will check the packet with the maintained states to match the packet with particular ongoing connection. Hence, the firewall keeps track of the connections itself.

2) Stateless Firewall:
In this case, we are simply implementing traditional firewall which does only checking of each packet. It does not maintain any states like Stateful Firewall. That is, it does not keep track of ongoing connection. Rather, it simply takes each packet as individuatl and tries to check the packet with the given firewall rules. Upon matching firewall rule, it carries out associated actions. 

