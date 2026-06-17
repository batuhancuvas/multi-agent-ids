from scapy.all import sniff

print("Listening on enp0s8... Send ping/traffic from Kali.")
print("Will stop after capturing 10 packets.\n")

def show(pkt):
    print(pkt.summary())

sniff(iface="enp0s8", count=10, prn=show)

print("\nTest complete: scapy can capture packets!")