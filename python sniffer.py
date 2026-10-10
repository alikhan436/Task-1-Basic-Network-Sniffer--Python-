from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] IP Packet: {src_ip} --> {dst_ip} | Protocol: {proto}")

        # Check for payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload: {payload[:30]}")
        print("-" * 50)

def main():
    print("Starting Network Sniffer (Scapy)... Press Ctrl+C to stop.")
    # Capture 20 packets
    sniff(prn=packet_callback, count=20, store=0)

if __name__ == "__main__":
    main()