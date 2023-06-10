import argparse
import socket
import struct
import os
from atpbar import atpbar, register_reporter, find_reporter, flush
from progressbar import Percentage, Bar, ETA, AdaptiveETA
import concurrent.futures 
import numpy as np

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.all import *
from scapy.data import ETH_P_IP, IP_PROTOS
import pandas as pd

MAX_ENTRIES_PER_FILE = 1000000

def gen_packet(entry_pd):
    pkt = None

    entry = entry_pd.to_dict()

    pkt = Ether()
            
    if pd.isna(entry['hdr.ethernet.src_mac']) or not entry['hdr.ethernet.src_mac']:
        pkt.src = "00:00:00:00:00:00"
    else:
        pkt.src = entry['hdr.ethernet.src_mac']
    
    if pd.isna(entry['hdr.ethernet.dst_mac']) or not entry['hdr.ethernet.dst_mac']:
        pkt.dst = "00:00:00:00:00:00"
    else:
        pkt.dst = entry['hdr.ethernet.dst_mac']
    
    if pd.isna(entry['hdr.ethernet.type']) or not entry['hdr.ethernet.type']:
        pkt.type = 0x800
    else:
        pkt.type = entry['hdr.ethernet.type']
    
    if pkt.getlayer(Ether).type == ETH_P_IP:
        if pd.isna(entry['hdr.ipv4.src_addr']) or not entry['hdr.ipv4.src_addr']:
            # print("Source IP address is not set")
            return None
        if pd.isna(entry['hdr.ipv4.dst_addr']) or not entry['hdr.ipv4.dst_addr']:
            # print("Destination IP address is not set")
            return None
        
        ip = IP(src=entry['hdr.ipv4.src_addr'], dst=entry['hdr.ipv4.dst_addr'], ttl=entry['hdr.ipv4.ttl'], proto=entry['hdr.ipv4.protocol'])
        ip.version = entry["hdr.ipv4.version"]
        ip.ihl = entry["hdr.ipv4.ihl"]
        ip.tos = entry["hdr.ipv4.tos"]
        ip.len = entry["hdr.ipv4.len"]
        ip.id = entry["hdr.ipv4.id"]
        ip.flags = entry["hdr.ipv4.flags"]
        ip.frag = entry["hdr.ipv4.frag"]
        ip.chksum = entry["hdr.ipv4.checksum"]
        pkt = pkt / ip
        if entry['hdr.ipv4.protocol'] == IP_PROTOS.tcp:
            tcp = TCP(sport=entry['hdr.tcp.src_port'], dport=entry['hdr.tcp.dst_port'], flags=entry['hdr.tcp.flags'], seq=entry['hdr.tcp.seq'], ack=entry['hdr.tcp.ack'], window=entry['hdr.tcp.window'], chksum=entry['hdr.tcp.checksum'])
            pkt = pkt / tcp
        elif entry['hdr.ipv4.protocol'] == IP_PROTOS.udp:
            udp = UDP(sport=entry['hdr.udp.src_port'], dport=entry['hdr.udp.dst_port'], chksum=entry['hdr.udp.checksum'])
            pkt = pkt / udp
        elif entry['hdr.ipv4.protocol'] == IP_PROTOS.icmp:
            icmp = ICMP(type=entry['hdr.icmp.type'], code=entry['hdr.icmp.code'], chksum=entry['hdr.icmp.checksum'])
            icmp.id = entry['hdr.icmp.id']
            icmp.seq = entry['hdr.icmp.seq']
            pkt = pkt / icmp
        else:
            # print(f"Unknown protocol: {entry['hdr.ipv4.protocol']}")
            return None
    else:
        # print(f"Unknown ethernet type: {entry['hdr.ethernet.type']}")
        return None

    
    if pkt is not None:
        pkt.time = entry['tstamp']
        pkt.len = entry['pktsize']
        if pkt.len != len(pkt):
            # Add padding
            # print("Adding padding of length: ", pkt.len - len(pkt))
            pkt = pkt / Raw(b'\x00' * (pkt.len - len(pkt)))

    return pkt


def parse_and_write_file(data_frame, start, end, write_file, total_tasks, task_idx):
    maxentries = int(end - start)
    tot_pbar = maxentries

    with PcapNgWriter(write_file) as writer:
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < maxentries:
                entry = data_frame.iloc[start + j]
                pkt = gen_packet(entry)
                if pkt is not None:
                    writer.write(pkt)
        writer.flush()

    return write_file

def parse_and_generate_pcap(data_frame, output_file):
    num_entries = len(data_frame.index)

    print(f"Number of entries: {num_entries}")

    # Split len by MAX_ENTRIES_PER_FILE to get the number of tasks
    total_tasks = int(np.ceil(num_entries / MAX_ENTRIES_PER_FILE))

    print(f"Total number of tasks will be {total_tasks}")

    files_to_write_list = list()
    tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")
    print(f"Temporary directory created: {tmp_dir.name}")
    for i in range(total_tasks):
        write_file = os.path.join(tmp_dir.name, f"{output_file}_{i}")
        files_to_write_list.append(write_file)

    final_list = list()
    task_order_list = list()
    task_idx = 0
    task_order_list.append(task_idx)

    start = 0
    end = 0
    reporter = find_reporter()
    future_to_file = dict()
    i = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(os.cpu_count(), 8), initializer=register_reporter, initargs=[reporter]) as executor:
        for file_to_write in files_to_write_list:
            task_idx += 1
            start = i * MAX_ENTRIES_PER_FILE
            end = min((i + 1) * MAX_ENTRIES_PER_FILE, num_entries)
            print(f"Task {task_idx} will write from {start} to {end}: file {file_to_write}")
            future_to_file[executor.submit(parse_and_write_file, data_frame, copy.deepcopy(start), copy.deepcopy(end), copy.deepcopy(file_to_write), copy.deepcopy(total_tasks), copy.deepcopy(task_idx))] = file_to_write
            i += 1
        flush()
        print("Waiting for tasks to complete...")
        print(f"Total tasks: {len(future_to_file)}")
        for future in concurrent.futures.as_completed(future_to_file):
            file = future_to_file[future]
            try:
                file_written = future.result()
                final_list.append(file_written)
            except Exception as exc:
                print('%r generated an exception: %s' % (file, exc))

    print(f"Created {len(final_list)} pcap files") 

    final_list.sort()

    print("Let's concatenate all the files")

    # create a single string with elements separated by a space
    files_to_write = ' '.join(final_list)

    print(f"The files to write are {files_to_write}")

    ret = subprocess.call(f"mergecap -a {files_to_write} -w {output_file}", shell=True)
    if ret != 0:
        print(f"Error merging files into {output_file}")
        return -1
    
    print(f"Finished merging all files into {output_file}")
    tmp_dir.cleanup()

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to read unique IP addresses from a pkl file and write them to a BPF cuckoo hash map')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_file", help="Output file name", required=True)

    args = parser.parse_args()

    output_file = args.output_file
    # Check if the input file exists
    if not os.path.exists(args.input_file):
        print(f"Input file {args.input_file} does not exist")
        exit(1)

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
        os.remove(output_file)
    except OSError:
        pass

    print(f"Reading input file {args.input_file}")
    data_frame = pd.read_pickle(args.input_file)
    data_frame = data_frame.convert_dtypes()

    print(f"Input file {args.input_file} read successfully")

    parse_and_generate_pcap(data_frame, output_file)

    print(f"Output file {output_file} written successfully")



    

