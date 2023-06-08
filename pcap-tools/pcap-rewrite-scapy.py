import argparse
import os
from atpbar import atpbar, register_reporter, find_reporter, flush
from progressbar import Percentage, Bar, ETA, AdaptiveETA
import concurrent.futures 

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter
from scapy.volatile import RandString
from scapy.all import *


widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]

MAX_FILE_SIZE=1000000

pbar_update_value = 0
total_tasks = 0

def mac_addr_to_bytes(mac):
    # Convert MAC address from string format to bytes
    return bytes(int(b, 16) for b in mac.split(':'))

def add_eth_hdr(pkt):
    if not pkt.haslayer(IP):
        return None

    eth = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x800)
    pkt = eth / pkt

    return pkt

def add_payload(pkt):
    remaining_size = pkt.wirelen - len(pkt)
    if remaining_size > 0:
        payload = Raw(RandString(size=remaining_size))
        pkt = pkt / payload

    return pkt

def modify_packet(pkt):
    pkt = add_payload(pkt)
    pkt = add_eth_hdr(pkt)

    return pkt

def parse_file_and_append(file_name, write_file, task_idx):
    global total_tasks

    local_pkt_dict = dict()

    command = f'capinfos {file_name} | grep "Number of packets" | tr -d " " | grep -oP "Numberofpackets=\K\d+"'
    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    maxentries = int(output.strip())
    tot_pbar = maxentries

    multiplier = (task_idx - 1) * MAX_FILE_SIZE
    with PcapNgReader(file_name) as pcap_reader:
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < maxentries:
                pkt = pcap_reader.read_packet()
                pkt = modify_packet(pkt)
                if pkt is not None:
                    local_pkt_dict[int(multiplier + j)] = (pkt.time, pkt)

    with PcapNgWriter(write_file) as writer:
        for _, buf in local_pkt_dict.values():
            writer.write(buf)

    return write_file


def modify_and_write_pcap(input_file, output_file):
    global total_tasks
    
    final_list = []
    file_list = []

    tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")
    ret = subprocess.call(f"editcap -c {MAX_FILE_SIZE} {input_file} {tmp_dir.name}/trace.pcap", shell=True)
    for file in os.listdir(tmp_dir.name):
        if file.endswith(".pcap"):
            write_file = os.path.splitext(file)[0] + "_write.pcap"
            file_list.append((file, write_file))

    file_list.sort(key=lambda x: x[0])

    prepend_str = tmp_dir.name + "/"
    file_list = [(prepend_str + a, prepend_str + b) for a, b in file_list]

    total_tasks = len(file_list)
    print(f"Total number of tasks will be {total_tasks}")

    task_order_list = list()
    task_idx = 0
    task_order_list.append(task_idx)

    reporter = find_reporter()
    future_to_file = dict()
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(os.cpu_count(), 8), initializer=register_reporter, initargs=[reporter]) as executor:
        for file, write_file in file_list:
            task_idx += 1
            future_to_file[executor.submit(parse_file_and_append, copy.deepcopy(file), copy.deepcopy(write_file), copy.deepcopy(task_idx))] = file
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
    parser = argparse.ArgumentParser(description='Program used to convert a PCAP into a numpy data structure (easier to work with)')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="Filename for input PCAP")
    parser.add_argument("-o", "--output-file", required=True, type=str, help="Filename for output parsed numpy file (for efficient loading)")
    parser.add_argument("-c", "--count", metavar="count", type=int, default=-1, help="Number of packets to read before stopping. Default is -1 (no limit).")
    parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")
    parser.add_argument("-j", "--json", action="store_true", help="Output JSON instead of numpy array")

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

    modify_and_write_pcap(input_file_path, output_file_path)

    print(f"Output file created: {output_file_path}")
