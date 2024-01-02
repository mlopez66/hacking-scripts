import argparse
import subprocess
import signal
import sys
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor

def close_application(sig, frame):
    print(colored("[-] Closing application...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)

def get_args():
    parser = argparse.ArgumentParser(description='ICMP Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Host or range of hosts to scan [Exemple: -t 10.10.10.1-10]")
    options = parser.parse_args()
    return options.target

def parse_target(target):
    target_splited = target.split('.')
    if len(target_splited) != 4:
        print(colored("[-] Invalid target", "red"))
        sys.exit(1)
    
    base_octets = '.'.join(target_splited[:3])
    if '-' in target_splited[3]:
        start, end = target_splited[3].split('-')
        return [f"{base_octets}.{i}" for i in range(int(start), int(end)+1)]
    else:
        return [target]


def scan_host(target):
    try:
        ping = subprocess.run(['ping', '-c', '1', target], timeout=1, stdout=subprocess.DEVNULL)
        if ping.returncode == 0:
            print(colored(f"[+] Host {target} is up", "green"))
    except subprocess.TimeoutExpired:
        pass

if __name__ == '__main__':
    targets = parse_target(get_args())
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(scan_host, targets)

    