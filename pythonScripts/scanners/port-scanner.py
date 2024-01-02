#!/usr/bin/env python3

import sys
import socket
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

SOCKETS = []

def close_application(sig, frame):
    print(colored(f"[!] Closing application...", "red"))
    for socket in SOCKETS:
        socket.close()
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)

def get_args():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target host to scan [Exemple: -t 10.10.10.1]")
    parser.add_argument("-p", "--port", dest="port", required=True, help="Port range [Exemple: -p 1-65535]")
    options = parser.parse_args()
    return options.target, options.port

def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    SOCKETS.append(sock)
    return sock

def scan_port(host, port):
    sock = create_socket()
    try:
        sock.connect((host, port))
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024)
        response = response.decode(errors="ignore").split("\n")

        print(colored(f"[+] Port {port} open", "green"))
        if response:
            for line in response:
                print(colored(line, "grey"))
    except (socket.timeout, ConnectionRefusedError):
        pass
    finally:
        sock.close()

def scan_ports(host, ports):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: scan_port(host, port), ports)

def parse_ports(ports_str):
    if ',' in ports_str:
        return map(int, ports_str.split(','))
    elif '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end + 1)
    else:
        return (int(ports_str),)
    
if __name__ == '__main__':
    host, ports_str = get_args()
    ports = parse_ports(ports_str)
    scan_ports(host, ports)

