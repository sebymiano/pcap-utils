import argparse
import re
import socket
import ipaddress
import struct

from randmac import RandMac
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandString


def parse_line(line):
    match = re.split(r'\t+', line.rstrip('\t'))
    return match


def build_packet_ipv4(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, proto):
    eth = Ether(src=src_mac, dst=dst_mac, type=0x800)
    ip = IP(src=src_ip, dst=dst_ip)
    if proto == UDP:
        ipproto = UDP(sport=src_port, dport=dst_port)
    else:
        ipproto = TCP(sport=src_port, dport=dst_port)

    pkt = eth / ip / ipproto
    if packetSize != 0 and len(pkt) < packetSize:
        remaining_size = packetSize - len(pkt)
        payload = Raw(RandString(size=remaining_size))
        return pkt / payload

    return eth / ip / ipproto


def parse_and_write_file(input_file, output_file):
    input_lines = 0
    with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
        line = input_file.readline()
        while line:
            input_lines += 1
            res = parse_line(line)
            assert res is not None, "Wrong format of the Classbench trace"

            src_ip = str(ipaddress.IPv4Address(int(res[0])))
            dst_ip = str(ipaddress.IPv4Address(int(res[1])))
            src_port = int(res[2])
            dst_port = int(res[3])
            proto = int(res[4])

            if proto == socket.IPPROTO_TCP:
                proto = TCP
            else:
                proto = UDP

            pkt = build_packet_ipv4(srcMAC, dstMAC, src_ip, dst_ip, src_port, dst_port, proto)

            wrpcap(output_file_path, [pkt], append=True)

            line = input_file.readline()

    return input_lines


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to generate pcap trace from Classbench generated traces')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="The Classbench trace input file")
    parser.add_argument("-o", "--output-file", required=True, type=str, help="The output pcap file ")
    parser.add_argument("-s", "--src-mac", type=str, help="Source MAC address to use in the generated pcap")
    parser.add_argument("-d", "--dst-mac", type=str, help="Destination MAC address to use in the generated pcap")
    parser.add_argument("-l", "--pkt-size", type=int, default=0, help="Size of the generated packet")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_path = args.output_file

    if args.src_mac is None:
        srcMAC = str(RandMac("00:00:00:00:00:00", True).mac)
    else:
        srcMAC = args.src_mac

    if args.dst_mac is None:
        dstMAC = str(RandMac("00:00:00:00:00:00", True).mac)
    else:
        dstMAC = args.dst_mac

    packetSize = args.pkt_size

    tot_input_lines = parse_and_write_file(input_file_path, output_file_path)

    print(f"Read and parsed a total of {tot_input_lines} from file")
    print(f"Output file created: {output_file_path}")
