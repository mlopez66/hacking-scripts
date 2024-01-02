from scapy.all import ARP, Ether, srp
import argparse

def get_args():
    parser = argparse.ArgumentParser(description='ARP Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target host or IP range to scan [Exemple: -t 192.168.1.0/24]")
    args = parser.parse_args()
    return args.target

def scan(target_ip):
    # Create an ARP request packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and capture the response
    result = srp(packet, timeout=1, verbose=0)[0]

    # Process the response
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Print the results
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")



if __name__ == '__main__':
    target_ip = get_args()
    scan(target_ip)
