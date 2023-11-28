import scapy.all as scapy
import time

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    # Extract relevant information from the packet
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Add your intrusion detection logic here
        if protocol == 6:  # TCP protocol
            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport

                # Check for a specific condition (e.g., large number of connections to a specific port)
                if dst_port == 22 and src_port > 1000:
                    print(f"Possible SSH brute force attack detected from {ip_src} to port {dst_port}")

        # Add more logic for other protocols as needed

# List of network interfaces to monitor
network_interfaces = ['eth0', 'wlan0', 'vlan0']

# Run the sniffing function for each network interface in a loop every 10 seconds
while True:
    for interface in network_interfaces:
        sniff_packets(interface)
    time.sleep(10)
