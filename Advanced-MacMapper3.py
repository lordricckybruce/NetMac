#!/bin/python3

import os
import subprocess
import threading
import csv
import json
from datetime import datetime
from scapy.all import ARP, Ether, srp

# Function to scan for Wi-Fi networks (platform-dependent)
def scan_wifi():
    print("Scanning for available Wi-Fi networks...")
    networks = []
    try:
        # Linux: Use nmcli to list networks
        result = subprocess.check_output("nmcli -f SSID,BSSID,SIGNAL dev wifi", shell=True, text=True)
        lines = result.splitlines()[1:]  # Skip the header
        for line in lines:
            parts = [item.strip() for item in line.split()]
            if len(parts) >= 2:
                ssid = parts[0]
                bssid = parts[1]
                signal = parts[2] if len(parts) > 2 else "N/A"
                networks.append({"SSID": ssid, "MAC": bssid, "Signal": signal})
    except Exception as e:
        print(f"Error scanning Wi-Fi networks: {e}")
    return networks

# Function to display and let the user select a Wi-Fi MAC address
def select_wifi_network(networks):
    if not networks:
        print("No Wi-Fi networks found.")
        return None
    print("\nAvailable Wi-Fi Networks:")
    for idx, net in enumerate(networks):
        print(f"{idx + 1}. SSID: {net['SSID']}, MAC: {net['MAC']}, Signal: {net['Signal']}")
    while True:
        try:
            choice = int(input("\nEnter the number of the Wi-Fi network to scan (0 to cancel): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(networks):
                return networks[choice - 1]
        except ValueError:
            print("Invalid input. Please enter a number corresponding to a Wi-Fi network.")

# Function to scan the selected network for devices
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
def mac_mapper_with_wifi():
    # Step 1: Scan for Wi-Fi networks
    networks = scan_wifi()
    selected_network = select_wifi_network(networks)
    if not selected_network:
        print("No network selected. Exiting.")
        return

    mac_address = selected_network["MAC"]
    print(f"Selected Wi-Fi Network:\nSSID: {selected_network['SSID']}, MAC: {mac_address}")

    # Step 2: Scan the network for devices
    network = "192.168.1.0/24"  # Placeholder for actual network
    print(f"Scanning network {network} for devices with MAC {mac_address}...")

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

    # Step 3: Display and save results
    if results:
        print(f"\nIP address(es) for MAC {mac_address}:")
        for res in results:
            print(f"IP: {res['IP Address']}, Detected At: {res['Detected At']}")
        save_to_csv(results)
        print("Results saved to results.csv.")
        save_to_json(results)
        print("Results saved to results.json.")
    else:
        print(f"No IP address found for MAC {mac_address} on network {network}.")

# Entry point
if __name__ == "__main__":
    mac_mapper_with_wifi()

