def dissect_and_resend_ptpv2(packet):
    if 'UDP' in packet and 'IP' in packet and Raw in packet:
        try:
            ptp_payload = packet[Raw].load
            ptp_packet = IEEE588(ptp_payload)

            if ptp_packet.messageType == 0x0:
                # Process Sync message
                pass
            elif ptp_packet.messageType == 0x8:
                # Process Follow_Up message
                time_before = ptp_packet.preciseOriginTimestamp
                fraction += 1 + (packet_count['0x8'] * 0.5)
                ptp_packet.preciseOriginTimestamp = time_before * fraction 
                ptp_packet.sequenceId += 1
                ptp_packetSend = (bytes(ptp_packet)).rstrip(b'\x00')
                ptp_packet_sending = IP(src=packet['IP'].src, dst=packet['IP'].dst) / \
                                      UDP(sport=320, dport=320) / \
                                      Raw(ptp_packetSend)
            elif ptp_packet.messageType == 0xb:
                # Process Announce message
                pass
            elif ptp_packet.messageType == 0x1:
                # Process other message types
                pass
            elif ptp_packet.messageType == 0x9:
                # Process other message types
                pass

            # If processing is successful, prepare and send the packet
            else:
                ptp_packet_sending = IP(src=packet['IP'].src, dst=packet['IP'].dst) / \
                                      UDP(sport=319 if ptp_packet.messageType == 0x0 else 320, dport=319 if ptp_packet.messageType == 0x0 else 320) / \
                                      Raw(bytes(ptp_packet))
            send(ptp_packet_sending, iface="enp1s0")
            print("Packet forwarded successfully")
        except struct.error:
            print("Packet discarded due to struct.error")
        except Exception as e:
            print("An error occurred:", e)
