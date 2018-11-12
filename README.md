@Author: Tan Lai Chian Alan / A0174404L
Date : 12 November 2018

1) Implementing Proxy-Arp Reply for the switch interface IP
- Handled in handleARPRequest() method
- Upon receiving ARP request from client/server, controller returns a ARP reply packet with MAC address of the switch to the client/server

2) Perform outbound Translation (Client to Server)
- Handled in handleICMPRequest() and handleICMPReply() methods
- Upon receiving ICMP echo REQUEST from client/server, controller prepares a new ICMP echo request packet containing the same ICMP payload, destinationProtocolAddress remains the same while sourceProtocolAddress is modified to that of the switch's corresponding IP address
- hashCode of ICMP payload data is used as Query ID, hashCode is stored in a ClientIPDataHashCodeMap, RouterMACDataHashCodeMap, and TimerDataHashCodeMap
- New ICMP echo request packet is sent out to target client/server
- Upon receiving ICMP echo REPLY from client/server, controller prepares a new ICMP echo REPLY packet containing the same ICMP payload, sourceProtocolAddress remains the same while destinationProtocolAddress is modified to that of the target address based on the hashCode (of the ICMP payload data) lookup in ClientIPDataHashCodeMap

3) Perform inbound Translation (Server to client)
- Handled in handleICMPRequest() and handleICMPReply() methods
- Upon receiving ICMP echo REQUEST from client/server, controller prepares a new ICMP echo request packet containing the same ICMP payload, destinationProtocolAddress remains the same while sourceProtocolAddress is modified to that of the switch's corresponding IP address
- hashCode of ICMP payload data is used as Query ID, hashCode is stored in a ClientIPDataHashCodeMap, RouterMACDataHashCodeMap, and TimerDataHashCodeMap
- New ICMP echo request packet is sent out to target client/server
- Upon receiving ICMP echo REPLY from client/server, controller prepares a new ICMP echo REPLY packet containing the same ICMP payload, sourceProtocolAddress remains the same while destinationProtocolAddress is modified to that of the target address based on the hashCode (of the ICMP payload data) lookup in ClientIPDataHashCodeMap

4) Handle Query ID Timeout
- At the start of program, a Timer thread is spawned that periodically iterates through TimerDataHashCodeMap to update and keep track of query lifespan
- Values of each query (hashCode) entry in TimerDataHashCodeMap is incremented by 1 every second
- When an entry hits or exceeds 120 (or of another desired timeout value), the hashCode entry is removed in TimerDataHashCodeMap, ClientIpDataHashCodeMap, and RouterMACHashCodeMap

5) With most of the gateways in internet performing NAT, how can two client machines communicate with each other directly? Give some example clients/software which do that.
- One of the most effective methods of establishing peer-to-peer communication between hosts on different private networks is known as "hole punching". This technique is widely used already in UDP-based applications such as online gaming. UDP hold punching enables two clients to set up a direct peer-to-peer UDP session with the help of a well-known rendezvous server, even if the clients are both behind NATs.

6) Challenges faced
- Understanding the concepts of ARP, NAT and ICMP before being able to make changes to NAT.java
- Found references on implementation of ARP Reply and ICMP Echo Replies but were coded in older versions of Floodlight, hence had to familiarize with the current Floodlight javadoc and make changes accordingly
- Building the floodlight controller takes 17-20 seconds every time, very time consuming to debug
- But otherwise this is a very interesting assignment!