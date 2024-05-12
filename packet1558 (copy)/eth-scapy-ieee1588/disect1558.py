from scapy.all import *

# Define a function to dissect IEEE 1588 packets
def dissect_ptpv2(packet):
    if packet.haslayer('IP') and packet.haslayer('UDP'):
        # Ensure the packet contains IP and UDP layers
        udp_payload = packet['UDP'].payload
        if isinstance(udp_payload, ieee1588):
            # Print packet summary
            print("IEEE 1588 Packet Summary:")
            print(packet.summary())
            # Extract and print IEEE 1588 fields
            print("IEEE 1588 Fields:")
            print(packet['UDP'].show())
            print(packet['ieee1588'].show())

# Read the captured packets and dissect IEEE 1588 packets
pkts = sniff(filter="udp and port 319", prn=dissect_ptpv2, count=10)
