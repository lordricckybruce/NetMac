#!/bin/python3

import re
import threading
import csv
import json
from datetime import datetime
from scapy.all import ARP, Ether, srp

# Function to validate MAC address format
def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac) is not None

# Function to validate subnet format
def is_valid_subnet(subnet):
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', subnet) is not None

# Function to perform ARP scan on a single subnet
def scan_network(mac_address, network, results, lock):
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered_packets = srp(packet, timeout=2, verbose=0)[0]

        for _, response in answered_packets:
            if response.hwsrc.lower() == mac_address.lower():
                with lock:
                    results.append({
                        "MAC Address": mac_address,
                        "IP Address": response.psrc,
                        "Detected At": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
    except Exception as e:
        print(f"Error scanning network {network}: {e}")

# Function to save results in CSV format
def save_to_csv(results, filename="results.csv"):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["MAC Address", "IP Address", "Detected At"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

# Function to save results in JSON format
def save_to_json(results, filename="results.json"):
    with open(filename, "w") as jsonfile:
        json.dump(results, jsonfile, indent=4)

# Main function
def find_ip_from_mac(mac_address, network="192.168.1.0/24", export_format="csv"):
    if not is_valid_mac(mac_address):
        print("Invalid MAC address format. Example: xx:xx:xx:xx:xx:xx")
        return

    if not is_valid_subnet(network):
        print("Invalid subnet format. Example: 192.168.1.0/24")
        return

    print(f"Scanning network {network} for MAC address {mac_address}...")

    results = []
    lock = threading.Lock()
    threads = []

    # Dynamically divide subnet for multithreading
    ip_prefix = network.split('/')[0].rsplit('.', 1)[0]
    for i in range(0, 256):
        subnet = f"{ip_prefix}.{i}/24"
        thread = threading.Thread(target=scan_network, args=(mac_address, subnet, results, lock))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    if results:
        print(f"IP address(es) for MAC {mac_address}: {', '.join([res['IP Address'] for res in results])}")
        if export_format == "csv":
            save_to_csv(results)
            print("Results saved to results.csv.")
        elif export_format == "json":
            save_to_json(results)
            print("Results saved to results.json.")
    else:
        print(f"No IP address found for MAC {mac_address} on network {network}.")

# Entry point
if __name__ == "__main__":
    target_mac = input("Enter the MAC address (e.g., xx:xx:xx:xx:xx:xx): ").strip()
    target_network = input("Enter the target network (default: 192.168.1.0/24): ").strip() or "192.168.1.0/24"
    export_format = input("Enter export format (csv/json, default: csv): ").strip().lower() or "csv"
    find_ip_from_mac(target_mac, target_network, export_format)

