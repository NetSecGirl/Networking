#!/usr/bin/env python
#! -*- coding: utf-8 -*-

# Three Way Handshaking using Scapy
# Listen on server on port 59007 (dport)
# Example nc 60.0.0.2 59007

from scapy.all import *

ip = IP(src="50.0.0.2", dst="60.0.0.2")
SYN = TCP(sport=20177, dport=59007, flags='S', seq=0)
SYNACK = sr1(ip/SYN)
# SYN-ACK
ACK=TCP(sport=20177, dport=59007, flags='A', seq=1, ack=SYNACK.seq + 1)
send(ip/ACK)

#payload = "stuff"
#PUSH = TCP(sport=20177, dport=59007, flags='PA', seq=1, ack=SYNACK.seq + 1)
#send(ip/PUSH/payload)

FIN = TCP(sport=20177, dport=59007, flags='FA', seq=1, ack=SYNACK.seq + 1)
FINACK=sr1(ip/FIN)

LASTACK=TCP(sport=20177, dport=59007, flags='A', seq=FINACK.ack, ack=FINACK.seq + 1)
send(ip/LASTACK)