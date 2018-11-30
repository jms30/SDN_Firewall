SDN_Firewall
============

SDN Firewall Project is about implementation of Firewall on SDN Controller by running bunch of Controller Application.

This repository consists of few Ryu Applications which are just python scripts written for running firewall functionality on Ryu controller. You need to have Ryu and Mininet installed on your device in order to run these Ryu applications. The Ryu applications are capable of ICMP, TCP and UDP firewall rules. 

There are 2 types of application each of which having 2 version. Namely,

* Inefficient Application
* Efficient Application


1) Inefficient Firewall:
It is named inefficient because it is **not** using Flow Tables functionality of Open vSwitches. It does not store any flow table entries extensively on the switch. Rather, it simply makes the switch to forward everything to the controller. Upon receiving each packet on controller, it takes necessary action (forwarding/discarding) to perform on the packet. 

2) Efficient Firewall:
This application uses Flow tables to store flow table entries on switch so that next time packets from that flow won't be forwarded to the controller. The switch will take decision based upon Flow table entries to forward to appropriate port or to reject the packet. Therefore, this applications are efficient in terms of packet exchange.

The two versions of firewalls are : Stateful & Stateless. 

1) Stateful firewall:
In this type of firewall, the states of the packets that passed through controller, are remembered. These states are maintained in order to detect the flow of the packet exchange between two communicating parties. The next time when a packet is received by the controller, it will check the packet with the maintained states to match the packet with particular ongoing connection. This way, the firewall keeps track of the connections itself.

2) Stateless Firewall:
This case implements traditional firewall which only checks each  arriving packet. It does **not** maintain any states like Stateful Firewall. That is, it does not keep track of ongoing connection. Rather, it simply takes each packet as individuatl and tries to check the packet with the given firewall rules. Upon matching firewall rule, it carries out associated actions, like forwarding to particular port or discarding the packet. 


With two types of applications and two versions of Firewall, this project consists of 4 different Ryu Firewall Applications. These are:

* Inefficient Stateful Firewall
* Inefficient Stateless Firewall
* Efficient(named secure) Stateful Firewall
* Efficient(named secure) Stateless Firewall

## What you have to do if you want to play around:

1. Have mininet and ryu installed on your computer
2. Get this repo.
3. Create mininet topology for 3 nodes, 1 open vswich and 1 controller (Check Appendix of Report pdf or guidebook of Ryu for creating such topology)
4. Read two example txts that represents how you can define Firewall Rules for Stateful and Stateless firewalls. 
5. Write down your rules inside Firewall.txt file
6. Run the appropriate Ryu application using ryu-manager on controller node.
7. For TCP case, use nc to listen tcp connection on one node and initiator on second node. This nodes should be on par with the firewall rules you have configured in Firewall.txt file. 
8. Make some text trasnfer between your nodes. You will see the process on controller and switch. If you are running "Efficient" applications, you can see the flow table entries on switch that are created by the controller.

For any queries about setup, please refer the Report file (2015-IDP-OpenFlow-Firewall.pdf) or drop me an email. 

P.S. Please bear the *worst* code quality. ;) 