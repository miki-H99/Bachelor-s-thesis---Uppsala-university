from scapy.all import *
from scapy.fields import BitEnumField, BitField, ByteField, ConditionalField, FlagsField, \
        LongField, ShortField, SignedByteField, XBitField, XByteField, XIntField, XStrFixedLenField
from scapy.layers.l2 import Ether
from scapy.packet import Packet 

from fields import PortIdentityField, TimestampField

import random

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
        ConditionalField(XStrFixedLenField("informationTlv", b'\x00' * 32, 32), lambda pkt: pkt.is_followup),
        ConditionalField(XStrFixedLenField("ClockIdentity", b'\x00' * 8, 8), lambda pkt: pkt.is_followup),

        ConditionalField(BitField("reserved4", 0, 80), lambda pkt: pkt.is_pdelay_req),
        ConditionalField(BitField("reserved5", 0, 80), lambda pkt: pkt.is_pdelay_req),

        ConditionalField(
            TimestampField("requestReceiptTimestamp", 0),
            lambda pkt: pkt.is_pdelay_resp),

        ConditionalField(
            TimestampField("responseOriginTimestamp", 0),
            lambda pkt: pkt.is_pdelay_resp_followup),

        ConditionalField(
            PortIdentityField("requestingPortIdentity", 0),
            lambda pkt: pkt.is_pdelay_resp or pkt.is_pdelay_resp_followup),
    ]

    @property
    def is_sync(self):
        return self.messageType == 0x0

    @property
    def is_followup(self):
        return self.messageType == 0x8

    @property
    def is_Announce(self):
        return self.messageType == 0xb

    @property
    def is_pdelay_req(self):
        return self.messageType == 0x2

    @property
    def is_pdelay_resp(self):
        return self.messageType == 0x3

    @property
    def is_pdelay_resp_followup(self):
        return self.messageType == 0xA

    def extract_padding(self, s):
        length = self.messageLength - len(self.fields_desc)
        return s[:length], s[length:]


packet_count = {"0x0": 0, "0x8": 0, "0xb": 0, "0x1": 0, '0x9': 0}  # 0x0: Sync, 0x8: Follow_up, 0xb: Announce
# 0x1: Delay_req_msg, 0x9: Delay_resp_msg
saved_packets = dict()

rand_precentage = list()

def dissect_and_resend_ptpv2(packet):
    if Raw in packet:
        packet[Ether].src = '64:31:50:18:80:18'
        ptp_payload = packet[Raw].load
        ptp_packet = IEEE588(ptp_payload)
        print('hej')

        if ptp_packet.messageType == 0x0:
            packet_count['0x0'] += 1
            print("Found a Sync message:")
            ptp_packet.sequenceId += 1

            if packet_count['0x0'] == 0:
                saved_packets['Sync'] = ptp_packet
            else:
                pass

        elif ptp_packet.messageType == 0x8:
            packet_count['0x8'] += 1
            print("Found a Follow_Up message:")
            time_before = ptp_packet.preciseOriginTimestamp
            precentage_of_packets = 0.01
            fraction = 1 + (packet_count['0x8'] * precentage_of_packets)
            pass

            if packet_count['0x8'] == 0:
                pass
            else:
                pass

        elif ptp_packet.messageType == 0xb:
            packet_count['0xb'] += 1

        elif ptp_packet.messageType == 0x1:
            packet_count['0x1'] += 1

        elif ptp_packet.messageType == 0x9:
            packet_count['0x9'] += 1

        print("\nPTPv2 Fields:")

        if ptp_packet.messageType == 0x0:
            pass
        elif ptp_packet.messageType == 0xb:
            print("----------------------------------")

            #ptp_packet.sourcePortIdentity = '64:31:50:18:80:18'
            ptp_packet.sequenceId += 1
            ptp_packetSend = (bytes(ptp_packet)).rstrip(b'\x00')
            byte_sequence = ptp_packetSend
            print(byte_sequence)
            print("-----------------------")
            modified_byte_sequence = byte_sequence.replace(b'\x18\xa9\x05\xff\xfe\xbc\xcel', b'\x64\x31\x50\xff\xfe\x18\x80\x18')
            #modified_byte_sequence2 = modified_byte_sequence.replace(b'\x80d1P\xff\xfe\x18\x80\x18\x00\x00\xa0', b'\x80\x64\x31\x50\xff\xfe\x18\x80\x18')
            #modified_byte_sequence3 = modified_byte_sequence2.replace(b'\x80d1P', b'\x80\x64\x31\x50')
            modified_byte_sequence4 = modified_byte_sequence.replace(b'\xf8', b'\xf5')
            ptp_packet_sending2 = Ether(src='18:a9:05:bc:ce:6c', dst="01:1b:19:00:00:00", type=0x88f7) /  Padding(Raw(modified_byte_sequence4))
            ptp_packet_sending3 = Raw(modified_byte_sequence4)
            #modified_byte_sequence = scapy.padding(modified_byte_sequence)
            print(modified_byte_sequence4)
            ptp_packet_sending4 = Padding(ptp_packet_sending2)
            sendp(ptp_packet_sending4, iface="enp1s0")
            time.sleep(1)

            print("----------------------------------")




pkts = sniff(filter="ether src 18:a9:05:bc:ce:6c", prn=dissect_and_resend_ptpv2, count=40)

print(pkts)
print(f"Number of packets captured:{packet_count}")