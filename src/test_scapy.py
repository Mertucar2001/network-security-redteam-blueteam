from scapy.all import IP, ICMP, send

# Sending a simple test packet (ICMP ping) to 127.0.0.1 (localhost/loopback)
packet = IP(dst="127.0.0.1") / ICMP()

print("Sending test packet...")
send(packet, verbose=True)
print("Packet sent. If no errors occurred, Scapy is working correctly.")