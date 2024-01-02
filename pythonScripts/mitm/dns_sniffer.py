#!/usr/bin/env python3

import argparse
import time
import scapy.all as scapy
from termcolor import colored
import signal


def close_application(sig, frame):
    print(colored("[-] Closing application...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)

def show_dns_packets(packet):
    keywords_to_exclude = ["google", "cloud", "bing", "static", "analytics"]
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode()
        if domain not in domains and not any(keyword in domain for keyword in keywords_to_exclude):
            domains.add(domain)
            print(f"[+] Domain: {domain}")

def sniff():
    global domains
    domains = set()
    interface = "eth0"
    scappy.sniff(iface=interface, filter="udp and port 53", prn=show_dns_packets, store=0)

if __name__ == "__main__":
    sniff()
