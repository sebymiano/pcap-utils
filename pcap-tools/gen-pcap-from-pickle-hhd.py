import argparse
import os
from atpbar import atpbar, register_reporter, find_reporter, flush
import concurrent.futures 
import numpy as np

import dpkt
import socket
import pandas as pd

import mmap
import psutil
import subprocess
import sys
import shutil
import time
import tempfile
import traceback
import binascii
import ipaddress
from loguru import logger

MAX_ENTRIES_PER_FILE = 1500000
MIN_ENTRIES_PER_FILE = 10000
class MetadataElem():
  def __init__(self):
    self.ethtype = 0
    self.protocol = 0
    self.src_ip = 0
    self.dst_ip = 0
    self.src_port = 0
    self.dst_port = 0
    self.size = 0
    self.tcp_fin_flag = False

  def __str__(self):
    str = f"Ethtype: {self.ethtype}\n"
    str += f"Proto: {self.protocol}\n"
    str += f"Source IP: {ipaddress.IPv4Address(self.src_ip)}\n"
    str += f"Dest IP: {ipaddress.IPv4Address(self.dst_ip)}\n"
    str += f"Source port: {self.src_port}\n"
    str += f"Dest port: {self.dst_port}\n"
    str += f"Size: {self.size}\n"
    str += f"tcp_fin_flag: {self.tcp_fin_flag}"
    return str

  def __bytes__(self):
    md_bytes = b''
    md_bytes += self.ethtype.to_bytes(2, 'big')
    md_bytes += self.protocol.to_bytes(1, 'big')
    md_bytes += self.src_ip.to_bytes(4, 'big')
    md_bytes += self.dst_ip.to_bytes(4, 'big')
    md_bytes += self.src_port.to_bytes(2, 'little')
    md_bytes += self.dst_port.to_bytes(2, 'little')
    md_bytes += self.size.to_bytes(4, 'little')
    md_bytes += self.tcp_fin_flag.to_bytes(1, 'little')
    return md_bytes

def init_pool(reporter, the_data_frame):
    register_reporter(reporter)
    global data_frame
    data_frame = the_data_frame

def gen_packet(entry_pd, entry_idx, cores, approach):
    pkt = None

    entry = entry_pd.to_dict()

    pkt = dpkt.ethernet.Ethernet()
            
    if pd.isna(entry['hdr.ethernet.src_mac']) or not entry['hdr.ethernet.src_mac']:
        pkt.src = b'\x00\x00\x00\x00\x00\x00'
    else:
        eth_src = str(entry['hdr.ethernet.src_mac'])
        if approach == "SHARED":
            eth_src_bytes = eth_src.split(':')
            eth_src_bytes[-1] = format(int(eth_src_bytes[-1], 16) + entry_idx % cores, '02x')
            eth_src = ':'.join(eth_src_bytes)
        pkt.src = binascii.unhexlify(eth_src.replace(':', ''))
    
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
        else:
            return None, None

        if ip.len > len(pkt.data):
            pad_len = ip.len - len(pkt.data)
            if pad_len > 0:
                pkt_bytes = bytes(pkt)
                pkt_bytes += os.urandom(pad_len)
                pkt = dpkt.ethernet.Ethernet(pkt_bytes)
    else:
        return None, None

    return pkt, entry['tstamp']

def get_md_from_pkt(pkt):
    md_elem = MetadataElem()
    # ETH_P_IP: 2048 (0x800)
    md_elem.ethtype = pkt.type
    ip = pkt.data
    md_elem.src_ip = int.from_bytes(ip.src, "big")
    md_elem.dst_ip = int.from_bytes(ip.dst, "big")
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        md_elem.protocol =  dpkt.ip.IP_PROTO_TCP
        md_elem.src_port = tcp.sport
        md_elem.dst_port = tcp.dport
        md_elem.tcp_fin_flag = tcp.flags & dpkt.tcp.TH_FIN
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        md_elem.protocol =  dpkt.ip.IP_PROTO_UDP
        md_elem.src_port = udp.sport
        md_elem.dst_port = udp.dport
    else:
        print(f"Unsupported layer type: {ip.p}")
        sys.exit(1)
    md_elem.size = len(pkt)
    # print(md_elem)
    return md_elem

def parse_and_write_file(start, end, write_file, total_tasks, task_idx, num_cores, approach):
    maxentries = int(end - start)
    tot_pbar = maxentries

    md_initial = MetadataElem()
    pkt_history = list()

    if num_cores > 1:
        pkt_history = [md_initial] * (num_cores - 1)

    if approach == "LOCAL" and start > 0 and num_cores > 1:
        # Need to generate the metadata for the first packet
        for i in range(1, start):
            entry = data_frame.iloc[start - i]
            pkt, ts = gen_packet(entry, start - i, num_cores, approach)
            if pkt is not None:
                curr_md = get_md_from_pkt(pkt)
                # update pkt_history
                pkt_history.insert(0, curr_md)
            if len(pkt_history) == num_cores - 1:
                break

    with open(write_file, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < maxentries:
                entry = data_frame.iloc[start + j]
                pkt, ts = gen_packet(entry, start + j, num_cores, approach)
                if pkt is not None:
                    if approach == "LOCAL":
                        md_bytes = b''
                        for x in pkt_history:
                            md_bytes += bytes(x)

                        eth_src = "10:10:10:10:10:10"
                        eth_dst = str(entry['hdr.ethernet.dst_mac'])
                        eth_src_bytes = eth_src.split(':')
                        eth_src_bytes[-1] = format(int(eth_src_bytes[-1], 16) + (start + j) % num_cores, '02x')
                        eth_src = ':'.join(eth_src_bytes)
                        eth_src = binascii.unhexlify(eth_src.replace(':', ''))
                        eth_dst = binascii.unhexlify(eth_dst.replace(':', ''))

                        new_pkt = dpkt.ethernet.Ethernet(src=eth_src, dst=eth_dst, type=dpkt.ethernet.ETH_TYPE_IP)
                        new_pkt.data = md_bytes + bytes(pkt)
                        if num_cores > 1:
                            curr_md = get_md_from_pkt(pkt)
                            # update pkt_history
                            pkt_history = pkt_history[1:]
                            pkt_history.append(curr_md)
                        pkt = new_pkt
                    writer.writepkt(pkt, ts=ts)

    return write_file

def parse_and_generate_pcap(data_frame, output_file, num_cores, approach):
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

    files_to_write_dict = dict()
    tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")
    logger.trace(f"Temporary directory created: {tmp_dir.name}")
    for i in range(1, num_cores + 1):
        files_to_write_dict[i] = list()
        for j in range(total_tasks):
            write_file = os.path.join(tmp_dir.name, f"{output_file_name}_{approach}_core{i:03}_{j:03}")
            files_to_write_dict[i].append(write_file)

    for core in range(1, num_cores + 1):
        final_list = list()
        task_idx = 0
        start = 0
        end = 0
        reporter = find_reporter()
        future_to_file = dict()
        i = 0
        logger.info(f"Generating pcap for core: {core}")
        files_to_write_list = files_to_write_dict[core]
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=min(phisical_cores, 64), initializer=init_pool, initargs=[reporter, data_frame]) as executor:
            for file_to_write in files_to_write_list:
                task_idx += 1
                start = i * possible_split
                end = min((i + 1) * possible_split, num_entries)
                # print(f"Task {task_idx} will write from {start} to {end}: file {file_to_write}")
                future_to_file[executor.submit(parse_and_write_file, start, end, file_to_write, total_tasks, task_idx, core, approach)] = file_to_write
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

        ret = subprocess.call(f"mergecap -a {files_to_write} -w {output_file}_{approach}_{core}.pcap", shell=True)
        if ret != 0:
            logger.error(f"Error merging files into {output_file}_{approach}_{core}")
            return -1
        
        logger.success(f"Finished merging all files into {output_file}_{approach}_{core}")

    tmp_dir.cleanup()

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to generate PCAP file from a pickle format')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_file", help="Output file name", required=True)
    parser.add_argument("--use-mmap", "-m", dest="use_mmap", help="Use mmap to read the input file", action="store_false", default=True)
    parser.add_argument("--num-cores", "-n", dest="num_cores", help="Number of cores to use (valid for the SHARED and LOCAL approach)", type=int, default=1)
    parser.add_argument("--approach", "-a", dest="approach", help="Approach to use to generate the PCAP file", choices=["FLOW_AFFINITY", "SHARED", "LOCAL"], default="FLOW_AFFINITY")
    parser.add_argument("--src-mac", "-s", dest="src_mac", help="Source MAC address to use in the generated PCAP file", default="00:00:00:00:00:01")
    parser.add_argument("--dst-mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")

    args = parser.parse_args()

    if args.approach == "SHARED" or args.approach == "LOCAL":
        logger.debug(f"Using {args.num_cores} cores")

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

    logger.success(f"Input file {args.input_file} read successfully") 

    logger.info(f"Modifying source and destination MAC addresses to {args.src_mac} and {args.dst_mac}")
    data_frame["hdr.ethernet.src_mac"] = args.src_mac
    data_frame["hdr.ethernet.dst_mac"] = args.dst_mac
    data_frame["hdr.ethernet.type"] = dpkt.ethernet.ETH_TYPE_IP

    data_frame = data_frame.convert_dtypes()
    parse_and_generate_pcap(data_frame, output_file, args.num_cores, args.approach)

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

    logger.success(f"Output file/s written successfully")



    

