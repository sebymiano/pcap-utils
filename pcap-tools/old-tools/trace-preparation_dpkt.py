import argparse
import os
import threading
import multiprocessing
from atpbar import atpbar, register_reporter, find_reporter, flush
from progressbar import Percentage, Bar, ETA, AdaptiveETA
import concurrent.futures 

import dpkt
import json
from typing import cast
import subprocess
import tempfile

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]

MAX_FILE_SIZE=1000000

pbar_update_value = 0
total_tasks = 0

class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('UTF8','replace')
        return json.JSONEncoder.default(self, obj)

def extract_pkt_info(pkt):
    packet_info = dict()

    # try to parse as Ethernet
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        packet_info['ethernet'] = {field: getattr(eth, field) for field in eth.__hdr_fields__}
        payload = eth.data
    except (dpkt.UnpackError, IndexError):
        # if that fails, try to parse as IP
        payload = dpkt.ip.IP(pkt)
    
    # Check the packet type
    if isinstance(payload, dpkt.ip.IP):
        ip = payload
        packet_info['ip'] = {field: getattr(ip, field) for field in ip.__hdr_fields__}

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            packet_info['ip']['tcp'] = {field: getattr(tcp, field) for field in tcp.__hdr_fields__}
        
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            packet_info['ip']['udp'] = {field: getattr(udp, field) for field in udp.__hdr_fields__}
            
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            packet_info['ip']['icmp'] = {field: getattr(icmp, field) for field in icmp.__hdr_fields__}
            
    elif isinstance(payload, dpkt.arp.ARP):
        arp = payload
        packet_info['arp'] = {field: getattr(arp, field) for field in arp.__hdr_fields__}
    
    return packet_info

def parse_file_and_append(file_name, task_idx):
    global total_tasks

    local_pkt_dict = dict()

    command = f'capinfos {file_name} | grep "Number of packets" | tr -d " " | grep -oP "Numberofpackets=\K\d+"'
    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    maxentries = int(output.strip())
    tot_pbar = maxentries

    val = "Frame "
    multiplier = (task_idx - 1) * MAX_FILE_SIZE
    with open(file_name, 'rb') as f:
        pcap_reader = dpkt.pcapng.Reader(f)
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < maxentries:
                timestamp, pkt = cast('tuple[float, bytes]', next(pcap_reader))
                
                packet_info = extract_pkt_info(pkt)
                local_pkt_dict[val + f" {multiplier + j}"] = packet_info             

    return local_pkt_dict


def parse_pcap_into_npy(input_file, count, debug):
    global total_tasks
    m = multiprocessing.Manager()
    file_lock = m.Lock()
    cv = threading.Condition()
    
    final_list = []
    arr = []
    i = 0
    file_list = []

    tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")
    ret = subprocess.call(f"editcap -c {MAX_FILE_SIZE} {input_file} {tmp_dir.name}/trace.pcap", shell=True)
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

    print(f"Created {len(final_list)} data frames.") 

    print("Creating final dictionary")
    final_result = {}
    for j in atpbar(range(len(final_list)), name=f"Concatenating results"):
        dictionary = final_list[j]
        for k, v in dictionary.items():
            final_result[k] = v
    # final_result = dict(ChainMap(*final_list))

    tmp_dir.cleanup()

    return final_result


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

    panda_df = parse_pcap_into_npy(input_file_path, args.count, args.verbose)
    print("Writing output file...")
    with open(output_file_path, 'w') as f:
        json.dump(panda_df, f, cls=BytesEncoder, default=str)

    print(f"Output file created: {output_file_path}")
