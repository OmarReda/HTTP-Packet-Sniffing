import sys
import re
import os
import socket
import struct
import binascii


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:           # 127.0.0.1 IP instead of 127001   
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    New_IP = '.'.join(f'{c}' for c in raw_ip_addr)
    return New_IP


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:    # Slice TCP
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    src_sliced = ip_packet_payload[0:2]
    #output = struct.unpack("!2s",src_sliced)
    source = int.from_bytes(src_sliced, byteorder='big')
    #print("TCP Source: ",output)
    print("TCP Source 2: ",source)

    dest_sliced = ip_packet_payload[2:4]
    destination = int.from_bytes(dest_sliced, byteorder='big')
    #print("TCP Destination: ",output2)
    print("TCP Destination 2: ",destination)

    Offset = ip_packet_payload[12] >>4
    print("Data Offset: ",Offset)

    index = Offset*4
    Data = ip_packet_payload[index:]
    print("Data: ",Data.decode("utf-8"))

    return TcpPacket(source, destination, Offset, Data)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:               # Slice IP
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    IHL = ip_packet[0] & 0b00001111
    print("IHL: ",IHL)

    protocol = ip_packet[9]
    print("Protocol: ",protocol)

    src_sliced = ip_packet[12:16]
    output = struct.unpack("!4s",src_sliced)
    #print(output[0])
    source = parse_raw_ip_addr(output[0])
    print("Source: ",source)

    dest_sliced = ip_packet[16:20]
    output2 = struct.unpack("!4s",dest_sliced)
    #print(output2[0])
    destination = parse_raw_ip_addr(output2[0])
    print("Destination: ",destination)

    index = 4 * IHL
    payload = ip_packet[index:]
    print("Payload: ",payload)
    return IpPacket(protocol, IHL, source, destination, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)

    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET,
                       socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))

    while True:
        # Receive packets and do processing here
        packet, addr = stealer.recvfrom(4096)
        print("\n")
        X = parse_network_layer_packet(packet)
        print("\n")
        Y = X.payload
        Z = parse_application_layer_packet(Y)

        pass
    pass

if __name__ == "__main__":
    main()
