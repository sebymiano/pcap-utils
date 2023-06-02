import argparse
import re
import socket
import ipaddress
import struct
import os
import threading
import multiprocessing
import mmap
from atpbar import atpbar, register_reporter, find_reporter, flush
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
import concurrent.futures 
import numpy as np

from randmac import RandMac
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandIP, RandString
from scapy.all import *
import pandas as pd

import json
from json import JSONEncoder

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]

MAX_FILE_SIZE=1000000

pbar_update_value = 0
total_tasks = 0
class NumpyArrayEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return JSONEncoder.default(self, obj)


def dottedQuadToNum(ip):
	"convert decimal dotted quad string to long integer"
	return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
	"convert long int to dotted quad string"
	return socket.inet_ntoa(struct.pack('>L',n))

header='tstamp,pktsize,captured_size,pkt_num,hdr.ethernet.src_mac,hdr.ethernet.dst_mac,hdr.ethernet.type,hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.ipv4.ttl,hdr.ipv4.protocol,hdr.ipv4.checksum,hdr.tcp.src_port,hdr.tcp.dst_port,hdr.tcp.checksum,hdr.tcp.flags,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.window,hdr.udp.src_port,hdr.udp.dst_port,hdr.udp.checksum,hdr.udp.len'
harr=header.split(',')
# header_loc_map=np.array(harr)
header_loc_map={harr[i]:i for i in range(len(harr))}

def parse_file_and_append(file_name, task_idx):
    global total_tasks

    local_pkt_list = list()

    command = f'capinfos {file_name} | grep "Number of packets" | tr -d " " | grep -oP "Numberofpackets=\K\d+"'
    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    maxentries = int(output.strip())
    tot_pbar = maxentries

    multiplier = (task_idx - 1) * MAX_FILE_SIZE

    with PcapReader(file_name) as pcap_reader:
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < maxentries:
                pkt = pcap_reader.read_packet()

                pdict = {}

                pdict['pktsize'] = pkt.wirelen
                pdict['captured_size'] = np.uint32(len(pkt))
                pdict['tstamp']=np.float128(pkt.time)
                pdict['pkt_num']=np.uint64(multiplier + j)

                if pkt.haslayer(Ether):
                    pdict['hdr.ethernet.src_mac']=np.uint64(mac2str(pkt[Ether].src).replace(':',''),16)
                    pdict['hdr.ethernet.dst_mac']=np.uint64(mac2str(pkt[Ether].dst).replace(':',''),16)
                    pdict['hdr.ethernet.type']=np.uint16(pkt[Ether].type)
                if pkt.haslayer(IP):
                    pdict['hdr.ipv4.ttl']=np.uint8(pkt[IP].ttl)
                    pdict['hdr.ipv4.protocol']=np.uint8(pkt[IP].proto)
                    pdict['hdr.ipv4.checksum']=np.uint16(pkt[IP].chksum)
                    pdict['hdr.ipv4.src_addr']=np.uint32(dottedQuadToNum(pkt[IP].src))
                    pdict['hdr.ipv4.dst_addr']=np.uint32(dottedQuadToNum(pkt[IP].dst))

                if pkt.haslayer(TCP):
                    pdict['hdr.tcp.src_port']=np.uint16(pkt[TCP].sport)
                    pdict['hdr.tcp.dst_port']=np.uint16(pkt[TCP].dport)
                    pdict['hdr.tcp.checksum']=np.uint16(pkt[TCP].chksum)
                    pdict['hdr.tcp.flags']=np.uint8(pkt[TCP].flags)
                    pdict['hdr.tcp.seq']=np.uint32(pkt[TCP].seq)
                    pdict['hdr.tcp.ack']=np.uint32(pkt[TCP].ack)
                    pdict['hdr.tcp.window']=np.uint16(pkt[TCP].window)

                if pkt.haslayer(UDP):
                    pdict['hdr.udp.src_port']=np.uint16(pkt[UDP].sport)
                    pdict['hdr.udp.dst_port']=np.uint16(pkt[UDP].dport)
                    pdict['hdr.udp.checksum']=np.uint16(pkt[UDP].chksum)
                    pdict['hdr.udp.len']=np.uint16(pkt[UDP].len)

                local_pkt_list.append(pdict)

                # def to_list(p):
                #     line=[]
                #     for h in harr:
                #         if (h not in p) or (p[h]==None):
                #             line.append(0)
                #         else:
                #             line.append(p[h])
                #     return line
                # local_pkt_list.append(tuple(to_list(pdict)))

    # arr=np.zeros((len(local_pkt_list)),dtype= np.dtype('f16,u4,u4,u8,u8,u8,u2,u4,u4,u1,u1,u2,u2,u2,u2,u1,u4,u4,u2,u2,u2,u2,u2'))
    # for i in range(len(local_pkt_list)):
    #     arr[i]=local_pkt_list[i]
    frame = pd.DataFrame.from_records(local_pkt_list, columns=header_loc_map)

    return frame


def parse_pcap_into_panda(input_file, count, debug):
    global total_tasks
    
    final_list = []
    arr = []
    file_list = []

    tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")
    ret = subprocess.call(f"editcap -c {MAX_FILE_SIZE} {input_file} {tmp_dir.name}/trace.pcap", shell=True)
    if ret != 0:
        print("editcap failed. Are you sure you have it installed?")
        exit(-1)

    for file in os.listdir(tmp_dir.name):
        if file.endswith(".pcap"):
            file_list.append(file)

    file_list.sort()

    file_list = [tmp_dir.name + "/" + s for s in file_list]

    total_tasks = len(file_list)
    print(f"Total number of tasks will be {total_tasks}")

    task_order_list = list()
    task_idx = 0
    task_order_list.append(task_idx)

    reporter = find_reporter()
    future_to_file = dict()
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(os.cpu_count(), 8), initializer=register_reporter, initargs=[reporter]) as executor:
        for file in file_list:
            task_idx += 1
            future_to_file[executor.submit(parse_file_and_append, copy.deepcopy(file), copy.deepcopy(task_idx))] = file
        flush()
        print("Waiting for tasks to complete...")
        print(f"Total tasks: {len(future_to_file)}")
        for future in concurrent.futures.as_completed(future_to_file):
            file = future_to_file[future]
            try:
                local_pkt_list = future.result()
                final_list.append(local_pkt_list)
            except Exception as exc:
                print('%r generated an exception: %s' % (file, exc))

    print(f"Created {len(final_list)} numpy arrays") 

    arr = pd.concat(final_list)
    # arr = np.concatenate(final_list)
    print(f"Final array size: {len(arr)} packets")
    tmp_dir.cleanup()

    # Sort the frame based on the timestamp
    # sorted_frame = arr.sort_values(by=['tstamp'], ascending=True)

    # Sort the frame based on the pkt_num
    sorted_frame = arr.sort_values(by=['pkt_num'], ascending=True)

    print(sorted_frame)

    return sorted_frame


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to convert a PCAP into a numpy data structure (easier to work with)')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="Filename for input PCAP")
    parser.add_argument("-o", "--output-file", required=True, type=str, help="Filename for output parsed numpy file (for efficient loading)")
    parser.add_argument("-c", "--count", metavar="count", type=int, default=-1, help="Number of packets to read before stopping. Default is -1 (no limit).")
    parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_path = args.output_file

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    frame = parse_pcap_into_panda(input_file_path, args.count, args.verbose)

    print(f"Saving output file: {output_file_path}")
    # np.save(output_file_path, nparray)
    frame.to_pickle(output_file_path)
    # frame.to_csv(output_file_path, index=False)
    print(f"Output file created: {output_file_path}")
