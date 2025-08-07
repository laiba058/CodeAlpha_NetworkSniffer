from scapy.all import sniff, IP, Raw

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] Source IP: {ip_layer.src}")
        print(f"[+] Destination IP: {ip_layer.dst}")
        print(f"[+] Protocol: {ip_layer.proto}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"[+] Payload: {payload[:50]}...")
        else:
            print("[+] No Payload")
        print("-" * 50)

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, count=10)
