import argparse
import re
import socket
import ipaddress
import os
import threading
import multiprocessing
import queue
from progressbar import Percentage, Bar, ETA, AdaptiveETA
from concurrent.futures import ThreadPoolExecutor

from randmac import RandMac
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
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
    elif proto == socket.IPPROTO_ICMP:
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

def get_or_random_ip(ip):
    if int(ip) == 0:
        return str(RandIP())

    return str(ipaddress.IPv4Address(int(ip)))

def get_or_random_port(port):
    if int(port) == 0:
        return int(RandShort())

    return int(port)

def get_or_random_proto(proto):
    if int(proto) == 0:
        return random.choice([socket.IPPROTO_UDP, socket.IPPROTO_TCP])

    return int(proto)

def parse_line_and_build_pkt(lines_list, lock, cv, i, order_list, result_queue):
    global pbar_update_value
    pkt_list = list()
    tot_pbar = len(lines_list) + 1
    # with cv:
    #     cv.notify_all()
    # for j in atpbar(range(tot_pbar), name=f"Task {i}"):
    for j in range(tot_pbar):
        if j < len(lines_list):
            line = lines_list[j]
            res = parse_line(line)
            assert res is not None, "Wrong format of the Classbench trace"

            src_ip = get_or_random_ip(res[0])
            dst_ip = get_or_random_ip(res[1])
            src_port = get_or_random_port(res[2])
            dst_port = get_or_random_port(res[3])
            proto = get_or_random_proto(res[4])

            pkt = build_packet_ipv4(srcMAC, dstMAC, src_ip, dst_ip, src_port, dst_port, proto)
            pkt_list.append(pkt) 

        if j == len(lines_list):
            with cv:
                previous_idx = i - 1
                while previous_idx not in order_list:
                    cv.wait(1.0)    # Wait one second
                
                result_queue.put(pkt_list)   
                order_list.append(i)
                cv.notify_all()  


def pcap_writer(output_file, result_queue, producers_completed):
    with PcapWriter(output_file, append=True, sync=True) as pktdump:
        aggregated_list = list()
        while not producers_completed or not result_queue.empty():
            try:
                result = result_queue.get(block=True, timeout=1.0)
                print("Got value from queue")
            except queue.Empty:
                continue

            aggregated_list += result
            if len(aggregated_list) > 5000:
                print("Dump file")
                pktdump.write(aggregated_list)
                aggregated_list.clear()

            result_queue.task_done()

        if len(aggregated_list) > 0:
            print("Dump file")
            pktdump.write(aggregated_list)
        
    print("Consumer terminated")


def parse_and_write_file(input_file):
    m = multiprocessing.Manager()
    file_lock = m.Lock()
    cv = multiprocessing.Condition()
    with open(input_file_path, 'r') as input_file:
        maxlines = sum(1 for _ in input_file)
        input_file.seek(0)
        line = input_file.readline()
        
        lines_list = list()
        task_order_list = m.list()
        task_idx = 0
        task_order_list.append(task_idx)

        remaining = maxlines

        chunk_size = 1000

        producers_completed = False
        result_queue = multiprocessing.JoinableQueue(maxsize=500)

        consumer = threading.Thread(target=pcap_writer, args=(output_file_path, result_queue, producers_completed))

        consumer.start()
        
        with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
            while line:
                lines_list.append(line)

                if len(lines_list) == min(remaining, chunk_size):
                    task_idx += 1
                    executor.submit(parse_line_and_build_pkt, copy.deepcopy(lines_list), file_lock, cv, copy.deepcopy(task_idx), task_order_list, result_queue)
                    lines_list.clear()
                    remaining -= chunk_size
                    
                line = input_file.readline()

        producers_completed = True
        consumer.join()

    return maxlines


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to generate pcap trace from Classbench generated traces')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="The Classbench trace input file")
    parser.add_argument("-o", "--output-file", type=str, help="The output pcap file ")
    parser.add_argument("-s", "--src-mac", type=str, help="Source MAC address to use in the generated pcap")
    parser.add_argument("-d", "--dst-mac", type=str, help="Destination MAC address to use in the generated pcap")
    parser.add_argument("-l", "--pkt-size", type=int, default=0, help="Size of the generated packet")

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

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    tot_input_lines = parse_and_write_file(input_file_path)

    print(f"Read and parsed a total of {tot_input_lines} from file")
    print(f"Output file created: {output_file_path}")
