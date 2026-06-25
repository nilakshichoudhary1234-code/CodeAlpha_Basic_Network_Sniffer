from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("\n" + "=" * 50)

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

        print("Packet Summary :")
        print(packet.summary())

print("Starting Network Sniffer...")
print("Press Ctrl+C to stop.")

sniff(prn=packet_callback, store=False)