#!/usr/bin/env python3

import argparse
import re
import subprocess
import signal
from termcolor import colored

def close_application(sig, frame):
    print(colored("[!] Closing application...", "red"))
    exit(1)

signal.signal(signal.SIGINT, close_application)


def get_args():
    parser = argparse.ArgumentParser(description="Macchanger for network interface")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="Network interface name (Example: -i eth0)")
    parser.add_argument("-m", "--mac", required=True, dest="mac", help="New MAC address (Example: -m 00:11:22:33:44:55)")
    return parser.parse_args()


def is_valid_mac(mac):
    return re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac)


def is_valid_interface(interface):
    return re.match(r"^[a-zA-Z0-9]{2,}$", interface)


def change_mac(interface, mac):
    if is_valid_mac(mac) and is_valid_interface(interface):
        print(colored(f"[+] Changing MAC address for {interface} to {mac}", "green"))
        subprocess.run(["ifconfig", interface, "down"])
        subprocess.run(["ifconfig", interface, "hw", "ether", mac])
        subprocess.run(["ifconfig", interface, "up"])
        print(colored(f"[+] MAC address changed to {mac}", "green"))
    else:
        print(colored("[-] Invalid MAC address or interface", "red"))
        exit(1)


if __name__ == "__main__":
    args = get_args()
    change_mac(args.interface, args.mac)
