import argparse
import socket
import struct
import os
import mmap
from atpbar import atpbar
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
import numpy as np

from randmac import RandMac
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandIP, RandString
from scapy.all import *
from scapy.all import PcapReader, PcapWriter

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]


MAX_FILE_SIZE = 10000

def dottedQuadToNum(ip):
	"convert decimal dotted quad string to long integer"
	return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
	"convert long int to dotted quad string"
	return socket.inet_ntoa(struct.pack('>L',n))

Pack_formatstring="dIIHHHHHHHHH"
header='ig_intr_md.ingress_mac_tstamp,hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.ipv4.ttl,hdr.ipv4.protocol,hdr.ipv4.checksum,hdr.tcp.src_port,hdr.tcp.dst_port,hdr.tcp.checksum,hdr.udp.src_port,hdr.udp.dst_port,hdr.udp.checksum'
harr=header.split(',')
header_loc_map={harr[i]:i for i in range(len(harr))}

def build_packet_ipv4(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, proto, lenght):
    eth = Ether(src=src_mac, dst=dst_mac, type=0x800)
    ip = IP(src=src_ip, dst=dst_ip)
    if proto == socket.IPPROTO_UDP:
        ipproto = UDP(sport=src_port, dport=dst_port)
    elif proto == socket.IPPROTO_TCP:
        ipproto = TCP(sport=src_port, dport=dst_port)
    elif proto == socket.IPPROTO_ICMP:
        ipproto = ICMP()
    else:
        ipproto = UDP(sport=src_port, dport=dst_port)
        #assert False, f"Input file containing an unknown protocol number: {proto}"
    pkt = eth / ip / ipproto
    if lenght != 0 and len(pkt) < lenght:
        remaining_size = lenght - len(pkt)
        payload = Raw(RandString(size=remaining_size))
        return pkt / payload

    return eth / ip / ipproto

def parse_and_write_pcap(input_file, output_file, count, debug, add_payload):    
    cmd = f"/usr/bin/tshark -r {input_file}"
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    totLineOriginalFile = subprocess.check_output(('wc', '-l'), stdin=ps.stdout)
    ps.wait()
    totLineOriginalFile = int(totLineOriginalFile)
    # subprocess.run(["ls", "-l"])
    pbar = ProgressBar(widgets=widgets, maxval=totLineOriginalFile).start()
    count = 0
    with PcapWriter(output_file, append=True, sync=True) as pktdump:
        for pkt in PcapReader(input_file):
            wirelen = pkt.wirelen

            if pkt.haslayer(IP) and (pkt.haslayer(UDP) or pkt.haslayer(TCP)):
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
                
                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    proto = socket.IPPROTO_TCP
                
                if pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    proto = socket.IPPROTO_UDP

                new_pkt = build_packet_ipv4(srcMAC, dstMAC, src_ip, dst_ip, src_port, dst_port, proto, wirelen)
                pktdump.write(new_pkt)

            count += 1
            pbar.update(count)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to convert a CAIDA PCAP trace into a line-rate one')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="Filename for input PCAP")
    parser.add_argument("-o", "--output-file", required=True, type=str, help="Filename for output PCAP file")
    parser.add_argument("-s", "--src-mac", type=str, help="Source MAC address to use in the generated pcap")
    parser.add_argument("-d", "--dst-mac", type=str, help="Destination MAC address to use in the generated pcap")
    parser.add_argument("-c", "--count", metavar="count", type=int, default=-1, help="Number of packets to read before stopping. Default is -1 (no limit).")
    parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")
    parser.add_argument("-p","--payload", action="store_true", help="Add payload to the trace.")

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

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    parse_and_write_pcap(input_file_path, output_file_path, args.count, args.verbose, args.payload)

    print(f"Output file created: {output_file_path}")
