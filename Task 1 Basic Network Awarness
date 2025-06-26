# Importing required library
from scapy.all import sniff, IP, TCP, UDP, Raw

# Callback function to process each captured packet
def process_packet(packet):
    # Check if packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Determine protocol type
        proto_name = ""
        if packet.haslayer(TCP):
            proto_name = "TCP"
        elif packet.haslayer(UDP):
            proto_name = "UDP"
        else:
            proto_name = f"Protocol Number {protocol}"

        # Extract payload if available
        payload = ""
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                payload = payload.decode(errors='ignore')
            except:
                payload = "Non-decodable payload"

        # Display captured packet information
        print(f"\n[+] Packet Captured!")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto_name}")
        print(f"    Payload        : {payload}")

# Start sniffing packets (interface can be specified if needed)
print("[*] Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)
