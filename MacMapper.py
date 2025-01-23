#!/usr/bin/env python3
import re
import threading
from scapy.all import ARP, Ether, srp

# Function to validate MAC address format
def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac) is not None

# Function to validate subnet format
def is_valid_subnet(subnet):
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', subnet) is not None

# Function to perform ARP scan
def scan_network(mac_address, network, results):
    try:
        # Create ARP request packet
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send the packet and capture the response
        answered_packets = srp(packet, timeout=2, verbose=0)[0]

        # Check for matching MAC address
        for _, response in answered_packets:
            if response.hwsrc.lower() == mac_address.lower():
                results.append(response.psrc)
    except Exception as e:
        print(f"Error during network scan: {e}")

# Main function
def find_ip_from_mac(mac_address, network="192.168.1.0/24"):
    if not is_valid_mac(mac_address):
        print("Invalid MAC address format. Example of valid MAC: xx:xx:xx:xx:xx:xx")
        return None

    if not is_valid_subnet(network):
        print("Invalid subnet format. Example of valid subnet: 192.168.1.0/24")
        return None

    print(f"Scanning network {network} for MAC address {mac_address}...")
    results = []
    threads = []

    # Multithreaded scan for large networks
    ip_prefix = network.split('/')[0].rsplit('.', 1)[0]
    for i in range(0, 256):
        subnet = f"{ip_prefix}.{i}/24"
        thread = threading.Thread(target=scan_network, args=(mac_address, subnet, results))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    if results:
        print(f"IP address(es) for MAC {mac_address}: {', '.join(results)}")
        with open("results.txt", "w") as file:
            file.write(f"MAC Address: {mac_address}\nIP Address(es): {', '.join(results)}\n")
        print("Results saved to results.txt.")
    else:
        print(f"No IP address found for MAC {mac_address} on network {network}.")

# Entry point
if __name__ == "__main__":
    target_mac = input("Enter the MAC address (e.g., xx:xx:xx:xx:xx:xx): ").strip()
    target_network = input("Enter the target network (default: 192.168.1.0/24): ").strip() or "192.168.1.0/24"
    find_ip_from_mac(target_mac, target_network)

