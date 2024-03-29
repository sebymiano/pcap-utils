import argparse
import re
import socket
import ipaddress
import os
import threading
import multiprocessing
from atpbar import atpbar
from progressbar import Percentage, Bar, ETA, AdaptiveETA
from concurrent.futures import ThreadPoolExecutor

from randmac import RandMac
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandIP, RandString
from scapy.all import *

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]


pbar_update_value = 0

def parse_line(line):
    match = re.split(r'\t+', line.rstrip('\t'))
    return match


def build_packet_ipv4(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, proto):
    eth = Ether(src=src_mac, dst=dst_mac, type=0x800)
    ip = IP(src=src_ip, dst=dst_ip)
    if proto == socket.IPPROTO_UDP:
        ipproto = UDP(sport=src_port, dport=dst_port)
    elif proto == socket.IPPROTO_TCP:
        ipproto = TCP(sport=src_port, dport=dst_port)
    elif proto == socket.IPPROTO_ICMP and not noICMP:
        ipproto = ICMP()
    else:
        ipproto = UDP(sport=src_port, dport=dst_port)
        #assert False, f"Input file containing an unknown protocol number: {proto}"

    pkt = eth / ip / ipproto
    if packetSize != 0 and len(pkt) < packetSize:
        remaining_size = packetSize - len(pkt)
        payload = Raw(RandString(size=remaining_size))
        return pkt / payload

    return eth / ip / ipproto

def get_or_random_ip(ip, src=True):
    if int(ip) == 0:
        # return str(RandIP())
        if src:
            return randomSrcIP
        else:
            return randomDstIP

    return str(ipaddress.IPv4Address(int(ip)))

def get_or_random_port(port, src=True):
    if int(port) == 0:
        # return int(RandShort())
        if src:
            return randomSrcPort
        else:
            return randomDstPort

    return int(port)

def get_or_random_proto(proto):
    if int(proto) == 0:
        return random.choice([socket.IPPROTO_UDP, socket.IPPROTO_TCP])

    return int(proto)

def parse_line_and_build_pkt(lines_list, lock, cv, i, order_list, pktdump):
    global pbar_update_value
    pkt_list = list()
    tot_pbar = len(lines_list)
    # with cv:
    #     cv.notify_all()
    for j in atpbar(range(tot_pbar), name=f"Task {i}"):
    #for j in range(tot_pbar):
        if j < len(lines_list):
            line = lines_list[j]
            res = parse_line(line)
            assert res is not None, "Wrong format of the Classbench trace"

            src_ip = get_or_random_ip(res[0])
            dst_ip = get_or_random_ip(res[1], src=False)
            src_port = get_or_random_port(res[2])
            dst_port = get_or_random_port(res[3], src=False)
            proto = get_or_random_proto(res[4])

            pkt = build_packet_ipv4(srcMAC, dstMAC, src_ip, dst_ip, src_port, dst_port, proto)
            pkt_list.append(pkt) 

        if j == len(lines_list) - 1:
            with cv:
                while order_list.count(i-1) == 0:
                    cv.wait()    # Wait one second
            with lock:
                pktdump.write(pkt_list)
            with cv:
                order_list.append(i)
                cv.notify_all()


def parse_and_write_file(input_file):
    m = multiprocessing.Manager()
    file_lock = m.Lock()
    cv = threading.Condition()
    with open(input_file_path, 'r') as input_file:
        maxlines = sum(1 for _ in input_file)
        input_file.seek(0)
        line = input_file.readline()
        
        lines_list = list()
        task_order_list = list()
        task_idx = 0
        task_order_list.append(task_idx)

        remaining = maxlines

        chunk_size = 10000
        with PcapWriter(output_file_path, append=True, sync=True) as pktdump:
            with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
                while line:
                    lines_list.append(line)

                    if len(lines_list) == min(remaining, chunk_size):
                        task_idx += 1
                        executor.submit(parse_line_and_build_pkt, copy.deepcopy(lines_list), file_lock, cv, copy.deepcopy(task_idx), task_order_list, pktdump)
                        lines_list.clear()
                        remaining -= chunk_size
                        
                    line = input_file.readline()

    return maxlines

def inject_udp_packets(num_udp_packets):
    eth = Ether(src=srcMAC, dst=dstMAC, type=0x800)
    i = 0
    for i in atpbar(range(num_udp_packets), name=f"Task udp miss"):
        ip_src = str(RandIP())
        ip_dst = str(RandIP())
        sport = int(RandShort())
        dport = int(RandShort())

        pkt = eth / IP(src=ip_src, dst=ip_dst) / UDP(sport=sport, dport=dport)

        if packetSize != 0 and len(pkt) < packetSize:
            remaining_size = packetSize - len(pkt)
            payload = Raw(RandString(size=remaining_size))
            pkt = pkt / payload

        wrpcap(output_file_path, [pkt], append=True, sync=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to generate pcap trace from Classbench generated traces')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="The Classbench trace input file")
    parser.add_argument("-o", "--output-file", type=str, help="The output pcap file ")
    parser.add_argument("-s", "--src-mac", type=str, help="Source MAC address to use in the generated pcap")
    parser.add_argument("-d", "--dst-mac", type=str, help="Destination MAC address to use in the generated pcap")
    parser.add_argument("-l", "--pkt-size", type=int, default=0, help="Size of the generated packet")
    parser.add_argument("--udp-percentage", type=int, default=0, help="Percentage of UDP traffic to inject in the trace")
    parser.add_argument("--no-icmp", type=bool, default=False, help="Generated packets are only TCP and/or UDP")

    args = parser.parse_args()

    input_file_path = args.input_file
    if args.output_file is None:
        output_file_path = input_file_path + ".pcap"
    else:
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
    noICMP = args.no_icmp
    udpPercentage = args.udp_percentage

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    randomSrcIP = str(RandIP())
    randomDstIP = str(RandIP())
    randomSrcPort = int(RandShort())
    randomDstPort = int(RandShort())

    tot_input_lines = parse_and_write_file(input_file_path)

    udp_packets = int((tot_input_lines * udpPercentage)/100)
    if udpPercentage > 0:
        inject_udp_packets(udp_packets)

    print(f"Read and parsed a total of {tot_input_lines} from file")
    print(f"Output file created: {output_file_path}")
