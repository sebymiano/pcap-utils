import argparse
import os
from atpbar import atpbar, register_reporter, find_reporter, flush
import concurrent.futures 
import numpy as np

import dpkt
import socket
import pandas as pd

import mmap
import copy
import subprocess
import sys
import shutil
import time
import tempfile
import traceback
import binascii
import psutil
from loguru import logger

MAX_ENTRIES_PER_FILE = 1500000
MIN_ENTRIES_PER_FILE = 10000

def init_pool(reporter, the_data_frame):
    register_reporter(reporter)
    global data_frame
    data_frame = the_data_frame

def gen_packet(entry_pd, pkt_size):
    pkt = None

    entry = entry_pd.to_dict()

    pkt = dpkt.ethernet.Ethernet()
            
    if pd.isna(entry['hdr.ethernet.src_mac']) or not entry['hdr.ethernet.src_mac']:
        pkt.src = b'\x00\x00\x00\x00\x00\x00'
    else:
        pkt.src = binascii.unhexlify(str(entry['hdr.ethernet.src_mac']).replace(':', ''))
    
    if pd.isna(entry['hdr.ethernet.dst_mac']) or not entry['hdr.ethernet.dst_mac']:
        pkt.dst = b'\x00\x00\x00\x00\x00\x00'
    else:
        pkt.dst = binascii.unhexlify(str(entry['hdr.ethernet.dst_mac']).replace(':', ''))

    if pd.isna(entry['hdr.ethernet.type']) or not entry['hdr.ethernet.type']:
        pkt.type = dpkt.ethernet.ETH_TYPE_IP
    else:
        pkt.type = entry['hdr.ethernet.type']
    
    if pkt.type == dpkt.ethernet.ETH_TYPE_IP:
        if pd.isna(entry['hdr.ipv4.src_addr']) or not entry['hdr.ipv4.src_addr'] or entry['hdr.ipv4.src_addr'] == "0":
            return None, None
        if pd.isna(entry['hdr.ipv4.dst_addr']) or not entry['hdr.ipv4.dst_addr'] or entry['hdr.ipv4.dst_addr'] == "0":
            return None, None
        
        ip = dpkt.ip.IP()
        ip.v = entry["hdr.ipv4.version"]
        ip.hl = entry["hdr.ipv4.ihl"]
        ip.tos = entry["hdr.ipv4.tos"]
        ip.len = entry["hdr.ipv4.len"]
        ip.id = entry["hdr.ipv4.id"]
        ip._flags_offset = entry["hdr.ipv4.flags"] << 13 | entry["hdr.ipv4.frag"]
        ip.ttl = entry['hdr.ipv4.ttl']
        ip.p = entry['hdr.ipv4.protocol']
        ip.sum = entry["hdr.ipv4.checksum"]
        ip.src = socket.inet_pton(socket.AF_INET, entry['hdr.ipv4.src_addr'])
        ip.dst = socket.inet_pton(socket.AF_INET, entry['hdr.ipv4.dst_addr'])
        if pd.notna(entry['hdr.ipv4.options.bytes']) and entry['hdr.ipv4.options.bytes'] and entry['hdr.ipv4.options.bytes'] != "0":
            tcp.opts = bytes.fromhex(entry['hdr.ipv4.options.bytes'])
        pkt.data = ip
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = dpkt.tcp.TCP()
            tcp.sport = entry['hdr.tcp.src_port']
            tcp.dport = entry['hdr.tcp.dst_port']
            tcp.seq = entry['hdr.tcp.seq']
            tcp.ack = entry['hdr.tcp.ack']
            tcp.off = entry['hdr.tcp.dataofs']
            tcp._rsv = entry['hdr.tcp.reserved']
            tcp.flags = entry['hdr.tcp.flags']
            tcp.win = entry['hdr.tcp.window']
            tcp.sum = entry['hdr.tcp.checksum']
            tcp.urp = entry['hdr.tcp.urgptr']
            if pd.notna(entry['hdr.tcp.options.bytes']) and entry['hdr.tcp.options.bytes'] and entry['hdr.tcp.options.bytes'] != "0":
                tcp.opts = bytes.fromhex(entry['hdr.tcp.options.bytes'])
            ip.data = tcp
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = dpkt.udp.UDP()
            udp.sport = entry['hdr.udp.src_port']
            udp.dport = entry['hdr.udp.dst_port']
            udp.sum = entry['hdr.udp.checksum']
            ip.data = udp
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            icmp = dpkt.icmp.ICMP(type=entry['hdr.icmp.type'], code=entry['hdr.icmp.code'])
            icmp.sum = entry['hdr.icmp.checksum']
            if entry['hdr.icmp.type'] == dpkt.icmp.ICMP_ECHO or entry['hdr.icmp.type'] == dpkt.icmp.ICMP_ECHOREPLY:
                icmp.data = dpkt.icmp.ICMP.Echo(id=entry['hdr.icmp.id'], seq=entry['hdr.icmp.seq']) # Assuming ICMP echo request/response
            ip.data = icmp
        else:
            return None, None

        if pkt_size > 0:
            ip.len = pkt_size
            
        if ip.len > len(pkt.data):
            pad_len = ip.len - len(pkt.data)
            if pad_len > 0:
                pkt_bytes = bytes(pkt)
                pkt_bytes += os.urandom(pad_len)
                pkt = dpkt.ethernet.Ethernet(pkt_bytes)
    else:
        return None, None

    return pkt, entry['tstamp']


def parse_and_write_file(start, end, write_file, total_tasks, task_idx, pkt_size):
    maxentries = int(end - start)
    tot_pbar = maxentries

    with open(write_file, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < maxentries:
                entry = data_frame.iloc[start + j]
                pkt, ts = gen_packet(entry, pkt_size)
                if pkt is not None:
                    writer.writepkt(pkt, ts=ts)

    return write_file

def parse_and_generate_pcap(data_frame, output_file, pkt_size):
    num_entries = len(data_frame.index)
    output_file_name = os.path.splitext(os.path.basename(output_file))[0]
    phisical_cores = psutil.cpu_count(logical=False)

    logger.info(f"Number of entries: {num_entries}")

    possible_split = int(np.ceil(num_entries / phisical_cores))
    
    if possible_split > MAX_ENTRIES_PER_FILE:
        # Split len by MAX_ENTRIES_PER_FILE to get the number of tasks
        total_tasks = int(np.ceil(num_entries / MAX_ENTRIES_PER_FILE))
        possible_split = MAX_ENTRIES_PER_FILE
    else:
        total_tasks = phisical_cores

    if possible_split < MIN_ENTRIES_PER_FILE:
        total_tasks = 1
        possible_split = MIN_ENTRIES_PER_FILE

    logger.trace(f"Total number of tasks will be {total_tasks} with {possible_split} entries per task")

    files_to_write_list = list()
    tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")
    logger.trace(f"Temporary directory created: {tmp_dir.name}")
    for i in range(total_tasks):
        write_file = os.path.join(tmp_dir.name, f"{output_file_name}_{i:03}")
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
    with concurrent.futures.ProcessPoolExecutor(max_workers=min(phisical_cores, 64), initializer=init_pool, initargs=[reporter, data_frame]) as executor:
        for file_to_write in files_to_write_list:
            task_idx += 1
            start = i * possible_split
            end = min((i + 1) * possible_split, num_entries)
            # print(f"Task {task_idx} will write from {start} to {end}: file {file_to_write}")
            future_to_file[executor.submit(parse_and_write_file, copy.deepcopy(start), copy.deepcopy(end), copy.deepcopy(file_to_write), copy.deepcopy(total_tasks), copy.deepcopy(task_idx), copy.deepcopy(pkt_size))] = file_to_write
            i += 1
        flush()
        logger.info("Waiting for tasks to complete...")
        logger.info(f"Total tasks: {len(future_to_file)}")
        for future in concurrent.futures.as_completed(future_to_file):
            file = future_to_file[future]
            try:
                file_written = future.result()
                final_list.append(file_written)
            except Exception as exc:
                logger.error('%r generated an exception: %s' % (file, exc))
                logger.error(traceback.format_exc())
                exit(-1)            

    logger.success(f"Created {len(final_list)} pcap files") 

    final_list.sort()

    logger.debug("Let's concatenate all the files")

    # create a single string with elements separated by a space
    files_to_write = ' '.join(final_list)

    logger.debug(f"The files to write are {files_to_write}")

    ret = subprocess.call(f"mergecap -a {files_to_write} -w {output_file}", shell=True)
    if ret != 0:
        logger.error(f"Error merging files into {output_file}")
        return -1
    
    logger.success(f"Finished merging all files into {output_file}")
    tmp_dir.cleanup()

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to generate PCAP file from a pickle format')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_file", help="Output file name", required=True)
    parser.add_argument("--use-mmap", "-m", dest="use_mmap", help="Use mmap to read the input file", action="store_false", default=True)
    parser.add_argument("--size", "-s", dest="size", help="Size of the pkt in Bytes", type=int, default=0)

    args = parser.parse_args()

    output_file = args.output_file
    # Check if the input file exists
    if not os.path.exists(args.input_file):
        logger.error(f"Input file {args.input_file} does not exist")
        exit(1)

    # check if mergecap is installed
    if not shutil.which("mergecap"):
        logger.error("mergecap not found. Please install wireshark.")
        sys.exit(1)
    
    # check if editcap is installed
    if not shutil.which("editcap"):
        logger.error("editcap not found. Please install wireshark.")
        sys.exit(1)

    # check if capinfos is installed
    if not shutil.which("capinfos"):
        logger.error("capinfos not found. Please install wireshark.")
        sys.exit(1)

    try:
        os.remove(output_file)
    except OSError:
        pass

    start_time = time.time()

    logger.info(f"Reading input file {args.input_file}. Use mmap: {args.use_mmap}")

    if args.use_mmap:
        with open(args.input_file, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, prot=mmap.ACCESS_READ) as mm:
                data_frame = pd.read_pickle(mm)
    else:
        data_frame = pd.read_pickle(args.input_file)

    data_frame = data_frame.convert_dtypes()
    logger.success(f"Input file {args.input_file} read successfully")

    parse_and_generate_pcap(data_frame, output_file, args.size)

    end_time = time.time()
    
    # Calculate the elapsed time
    elapsed_time = end_time - start_time

    # Convert elapsed time to hours, minutes, and seconds
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)

    # Print the elapsed time
    if hours >= 1:
        logger.info(f"Elapsed time: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds")
    elif minutes >= 1:
        logger.info(f"Elapsed time: {int(minutes)} minutes {int(seconds)} seconds")
    else:
        logger.info(f"Elapsed time: {int(seconds)} seconds")

    logger.success(f"Output file {output_file} written successfully")



    

