#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp

def get_ip_from_mac(mac_address, target_network="192.168.1.0/24"):
    # Create an ARP request packet
    arp = ARP(pdst=target_network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse the response
    for _, received in result:
        if received.hwsrc.lower() == mac_address.lower():
            return received.psrc
    return None

mac = "xx:xx:xx:xx:xx:xx"  # Replace with the MAC address
ip = get_ip_from_mac(mac)
if ip:
    print(f"IP address for {mac} is {ip}")
else:
    print("MAC address not found on the network.")

