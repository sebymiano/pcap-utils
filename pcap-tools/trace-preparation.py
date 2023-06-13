import argparse
import socket
import struct
import os
from atpbar import atpbar, register_reporter, find_reporter, flush
from progressbar import Percentage, Bar, ETA, AdaptiveETA
import concurrent.futures 
import numpy as np

from scapy.layers.inet import IP, TCP, UDP, ICMP, IPOption, TCPOptionsField
from scapy.layers.l2 import Ether
from scapy.all import *
import pandas as pd

from json import JSONEncoder
import mmap
import time

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

header_type_dict = {
    'tstamp': np.float128,
    'pktsize': np.uint32,
    'captured_size': np.uint32,
    'pkt_num': np.uint64,
    'hdr.ethernet.src_mac': np.uint64,
    'hdr.ethernet.dst_mac': np.uint64,
    'hdr.ethernet.type': np.uint16,
    'hdr.ipv4.version': np.uint8,
    'hdr.ipv4.ihl': np.uint8,
    'hdr.ipv4.tos': np.uint8,
    'hdr.ipv4.len': np.uint16,
    'hdr.ipv4.id': np.uint16,
    'hdr.ipv4.flags': np.uint8,
    'hdr.ipv4.frag': np.uint16,
    'hdr.ipv4.ttl': np.uint8,
    'hdr.ipv4.protocol': np.uint8,
    'hdr.ipv4.checksum': np.uint16,
    'hdr.ipv4.src_addr': np.uint32,
    'hdr.ipv4.dst_addr': np.uint32,
    'hdr.ipv4.options': object,
    'hdr.tcp.src_port': np.uint16,
    'hdr.tcp.dst_port': np.uint16,
    'hdr.tcp.seq': np.uint32,
    'hdr.tcp.ack': np.uint32,
    'hdr.tcp.dataofs': np.uint8,
    'hdr.tcp.reserved': np.uint8,
    'hdr.tcp.flags': np.uint8,
    'hdr.tcp.window': np.uint16,
    'hdr.tcp.checksum': np.uint16,
    'hdr.tcp.urgptr': np.uint16,
    'hdr.tcp.options': object,
    'hdr.udp.src_port': np.uint16,
    'hdr.udp.dst_port': np.uint16,
    'hdr.udp.checksum': np.uint16,
    'hdr.udp.len': np.uint16,
    'hdr.icmp.type': np.uint8,
    'hdr.icmp.code': np.uint8,
    'hdr.icmp.checksum': np.uint16,
    'hdr.icmp.id': np.uint16,
    'hdr.icmp.seq': np.uint16
}

header_type_dict2 = {
    'tstamp': np.float128,
    'pktsize': np.uint32,
    'captured_size': np.uint32,
    'pkt_num': np.uint64,
    'hdr.ethernet.src_mac': str,
    'hdr.ethernet.dst_mac': str,
    'hdr.ethernet.type': np.uint16,
    'hdr.ipv4.version': np.uint8,
    'hdr.ipv4.ihl': np.uint8,
    'hdr.ipv4.tos': np.uint8,
    'hdr.ipv4.len': np.uint16,
    'hdr.ipv4.id': np.uint16,
    'hdr.ipv4.flags': np.uint8,
    'hdr.ipv4.frag': np.uint16,
    'hdr.ipv4.ttl': np.uint8,
    'hdr.ipv4.protocol': np.uint8,
    'hdr.ipv4.checksum': np.uint16,
    'hdr.ipv4.src_addr': str,
    'hdr.ipv4.dst_addr': str,
    'hdr.ipv4.options': object,
    'hdr.ipv4.options.bytes': object,
    'hdr.tcp.src_port': np.uint16,
    'hdr.tcp.dst_port': np.uint16,
    'hdr.tcp.seq': np.uint32,
    'hdr.tcp.ack': np.uint32,
    'hdr.tcp.dataofs': np.uint8,
    'hdr.tcp.reserved': np.uint8,
    'hdr.tcp.flags': np.uint8,
    'hdr.tcp.window': np.uint16,
    'hdr.tcp.checksum': np.uint16,
    'hdr.tcp.urgptr': np.uint16,
    'hdr.tcp.options': object,
    'hdr.tcp.options.bytes': object,
    'hdr.udp.src_port': np.uint16,
    'hdr.udp.dst_port': np.uint16,
    'hdr.udp.checksum': np.uint16,
    'hdr.udp.len': np.uint16,
    'hdr.icmp.type': np.uint8,
    'hdr.icmp.code': np.uint8,
    'hdr.icmp.checksum': np.uint16,
    'hdr.icmp.id': np.uint16,
    'hdr.icmp.seq': np.uint16
}

def get_field_bytes(pkt, name):
     fld, val = pkt.getfield_and_val(name)
     return fld.i2m(pkt, val)

def get_pkt_info(pkt, pkt_num):
    pdict = {}
    pdict['pktsize'] = pkt.wirelen
    pdict['captured_size'] = np.uint32(len(pkt))
    pdict['tstamp']=np.float128(pkt.time)
    pdict['pkt_num']=np.uint64(pkt_num)

    if pkt.haslayer(Ether):
        pdict['hdr.ethernet.src_mac']=np.uint64(mac2str(pkt[Ether].src).replace(':',''),16)
        pdict['hdr.ethernet.dst_mac']=np.uint64(mac2str(pkt[Ether].dst).replace(':',''),16)
        pdict['hdr.ethernet.type']=np.uint16(pkt[Ether].type)

    if pkt.haslayer(IP):
        pdict['hdr.ipv4.version'] = np.uint8(pkt[IP].version)
        pdict['hdr.ipv4.ihl'] = np.uint8(pkt[IP].ihl)
        pdict['hdr.ipv4.tos'] = np.uint8(pkt[IP].tos)
        pdict['hdr.ipv4.len'] = np.uint16(pkt[IP].len)
        pdict['hdr.ipv4.id'] = np.uint16(pkt[IP].id)
        pdict['hdr.ipv4.flags'] = np.uint8(pkt[IP].flags)
        pdict['hdr.ipv4.frag'] = np.uint16(pkt[IP].frag)
        pdict['hdr.ipv4.ttl']=np.uint8(pkt[IP].ttl)
        pdict['hdr.ipv4.protocol']=np.uint8(pkt[IP].proto)
        pdict['hdr.ipv4.checksum']=np.uint16(pkt[IP].chksum)
        pdict['hdr.ipv4.src_addr']=np.uint32(dottedQuadToNum(pkt[IP].src))
        pdict['hdr.ipv4.dst_addr']=np.uint32(dottedQuadToNum(pkt[IP].dst))
        pdict['hdr.ipv4.options']=pkt[IP].options

    if pkt.haslayer(TCP):
        pdict['hdr.tcp.src_port']=np.uint16(pkt[TCP].sport)
        pdict['hdr.tcp.dst_port']=np.uint16(pkt[TCP].dport)
        pdict['hdr.tcp.seq']=np.uint32(pkt[TCP].seq)
        pdict['hdr.tcp.ack']=np.uint32(pkt[TCP].ack)
        pdict['hdr.tcp.dataofs']=np.uint8(pkt[TCP].dataofs)
        pdict['hdr.tcp.reserved']=np.uint8(pkt[TCP].reserved)
        pdict['hdr.tcp.flags']=pkt[TCP].flags
        pdict['hdr.tcp.window']=np.uint16(pkt[TCP].window)
        pdict['hdr.tcp.checksum']=np.uint16(pkt[TCP].chksum)
        pdict['hdr.tcp.urgptr']=np.uint16(pkt[TCP].urgptr)
        pdict['hdr.tcp.options']=pkt[TCP].options

    if pkt.haslayer(UDP):
        pdict['hdr.udp.src_port']=np.uint16(pkt[UDP].sport)
        pdict['hdr.udp.dst_port']=np.uint16(pkt[UDP].dport)
        pdict['hdr.udp.checksum']=np.uint16(pkt[UDP].chksum)
        pdict['hdr.udp.len']=np.uint16(pkt[UDP].len)

    if pkt.haslayer(ICMP):
        pdict['hdr.icmp.type']=np.uint8(pkt[ICMP].type)
        pdict['hdr.icmp.code']=np.uint8(pkt[ICMP].code)
        pdict['hdr.icmp.checksum']=np.uint16(pkt[ICMP].chksum)
        pdict['hdr.icmp.id']=np.uint16(pkt[ICMP].id)
        pdict['hdr.icmp.seq']=np.uint16(pkt[ICMP].seq)

    return pdict

def get_pkt_info2(pkt, pkt_num):
    pdict = {}
    pdict['pktsize'] = pkt.wirelen
    pdict['captured_size'] = len(pkt)
    pdict['tstamp']=pkt.time
    pdict['pkt_num']=pkt_num

    if pkt.haslayer(Ether):
        pdict['hdr.ethernet.src_mac']=pkt[Ether].src
        pdict['hdr.ethernet.dst_mac']=pkt[Ether].dst
        pdict['hdr.ethernet.type']=int(pkt[Ether].type)

    if pkt.haslayer(IP):
        pdict['hdr.ipv4.version'] = int(pkt[IP].version)
        pdict['hdr.ipv4.ihl'] = int(pkt[IP].ihl)
        pdict['hdr.ipv4.tos'] = int(pkt[IP].tos)
        pdict['hdr.ipv4.len'] = int(pkt[IP].len)
        pdict['hdr.ipv4.id'] = int(pkt[IP].id)
        pdict['hdr.ipv4.flags'] = int(pkt[IP].flags)
        pdict['hdr.ipv4.frag'] = int(pkt[IP].frag)
        pdict['hdr.ipv4.ttl']=int(pkt[IP].ttl)
        pdict['hdr.ipv4.protocol']=int(pkt[IP].proto)
        pdict['hdr.ipv4.checksum']=int(pkt[IP].chksum)
        pdict['hdr.ipv4.src_addr']=pkt[IP].src
        pdict['hdr.ipv4.dst_addr']=pkt[IP].dst
        pdict['hdr.ipv4.options']=pkt[IP].options
        pdict['hdr.ipv4.options.bytes']=get_field_bytes(pkt[IP], "options")

    if pkt.haslayer(TCP):
        pdict['hdr.tcp.src_port']=int(pkt[TCP].sport)
        pdict['hdr.tcp.dst_port']=int(pkt[TCP].dport)
        pdict['hdr.tcp.seq']=int(pkt[TCP].seq)
        pdict['hdr.tcp.ack']=int(pkt[TCP].ack)
        pdict['hdr.tcp.dataofs']=int(pkt[TCP].dataofs)
        pdict['hdr.tcp.reserved']=int(pkt[TCP].reserved)
        pdict['hdr.tcp.flags']=pkt[TCP].flags
        pdict['hdr.tcp.window']=int(pkt[TCP].window)
        pdict['hdr.tcp.checksum']=int(pkt[TCP].chksum)
        pdict['hdr.tcp.urgptr']=int(pkt[TCP].urgptr)
        pdict['hdr.tcp.options']=pkt[TCP].options
        pdict['hdr.tcp.options.bytes']=get_field_bytes(pkt[TCP], "options")

    if pkt.haslayer(UDP):
        pdict['hdr.udp.src_port']=int(pkt[UDP].sport)
        pdict['hdr.udp.dst_port']=int(pkt[UDP].dport)
        pdict['hdr.udp.checksum']=int(pkt[UDP].chksum)
        pdict['hdr.udp.len']=int(pkt[UDP].len)
    
    if pkt.haslayer(ICMP):
        pdict['hdr.icmp.type']=int(pkt[ICMP].type)
        pdict['hdr.icmp.code']=int(pkt[ICMP].code)
        pdict['hdr.icmp.checksum']=int(pkt[ICMP].chksum)
        if pkt[ICMP].id is not None:
            pdict['hdr.icmp.id']=int(pkt[ICMP].id)
        
        if pkt[ICMP].seq is not None:
            pdict['hdr.icmp.seq']=int(pkt[ICMP].seq)

    return pdict


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

                pdict = get_pkt_info2(pkt, multiplier + j)
                local_pkt_list.append(pdict)
    try:
        frame = pd.DataFrame.from_records(local_pkt_list, columns=header_type_dict2.keys())
        frame = frame.replace(np.nan,0)
        frame = frame.astype(header_type_dict2)
        frame = frame.replace("0.0", np.nan)
    except Exception as e:
        print(f"Error in task {task_idx}")
        print(e)
        exit(-1)

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
    parser.add_argument("-n", "--numpy", action="store_true", help="Output numpy array instead of pandas dataframe (default .pkl).")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_path = args.output_file

    # check if mergecap is installed
    if not shutil.which("mergecap"):
        print("mergecap not found. Please install wireshark.")
        sys.exit(1)
    
    # check if editcap is installed
    if not shutil.which("editcap"):
        print("editcap not found. Please install wireshark.")
        sys.exit(1)

    # check if capinfos is installed
    if not shutil.which("capinfos"):
        print("capinfos not found. Please install wireshark.")
        sys.exit(1)

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    start_time = time.time()

    frame = parse_pcap_into_panda(input_file_path, args.count, args.verbose)

    print(f"Saving output file: {output_file_path}")
    # np.save(output_file_path, nparray)
    if args.numpy:
        numpy_array = frame.to_numpy()
        np.save(output_file_path, numpy_array)
    else:
        frame.to_pickle(output_file_path)
    
    end_time = time.time()
    
    # Calculate the elapsed time
    elapsed_time = end_time - start_time

    # Convert elapsed time to hours, minutes, and seconds
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)

    # Print the elapsed time
    if hours >= 1:
        print(f"Elapsed time: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds")
    elif minutes >= 1:
        print(f"Elapsed time: {int(minutes)} minutes {int(seconds)} seconds")
    else:
        print(f"Elapsed time: {int(seconds)} seconds")

    print(f"Output file created: {output_file_path}")
