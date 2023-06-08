import argparse
import socket
import struct
import os
import threading
import multiprocessing
import mmap
from atpbar import atpbar
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
from concurrent.futures import ThreadPoolExecutor
import numpy as np

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


MAX_FILE_SIZE = 10000

pbar_update_value = 0
total_tasks = 0
class RawPcapReaderFD(RawPcapReader):
    """A stateful pcap reader. Each packet is returned as a string"""

    def __init__(self, fd):
        self.filename = "dummy"
        try:
            self.f = fd
            magic = self.f.read(4)
        except IOError:
            self.f = fd
            magic = self.f.read(4)
        if magic == "\xa1\xb2\xc3\xd4": #big endian
            self.endian = ">"
        elif  magic == "\xd4\xc3\xb2\xa1": #little endian
            self.endian = "<"
        else:
            raise Scapy_Exception("Not a pcap capture file (bad magic)")
        hdr = self.f.read(20)
        if len(hdr)<20:
            raise Scapy_Exception("Invalid pcap file (too short)")
        vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(self.endian+"HHIIII",hdr)

        self.linktype = linktype

# class PcapReader(RawPcapReaderFD):
#     def __init__(self, fd):
#         RawPcapReaderFD.__init__(self, fd)
#         try:
#             self.LLcls = conf.l2types[self.linktype]
#         except KeyError:
#             warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype,self.linktype))
#             self.LLcls = conf.raw_layer


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

def parse_file_and_append(file_name, lock, cv, task_idx, order_list, pktdump, add_payload=False):
    global total_tasks

    local_pkt_list = list()

    # with PcapReader(file_name) as pcap_reader:
    #     maxentries = sum(1 for _ in pcap_reader)

    tot_pbar = MAX_FILE_SIZE

    with PcapReader(file_name) as pcap_reader:
        for j in atpbar(range(tot_pbar), name=f"Task {task_idx}/{total_tasks}"):
            if j < MAX_FILE_SIZE:
                pkt = pcap_reader.read_packet()

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
                    local_pkt_list.append(new_pkt)

            if j == MAX_FILE_SIZE - 1:
                with cv:
                    while order_list.count(task_idx-1) == 0:
                        cv.wait()    # Wait one second
                with lock:
                    pktdump.write(local_pkt_list)
                with cv:
                    order_list.append(task_idx)
                    cv.notify_all()


def parse_and_write_pcap(input_file, output_file, count, debug, add_payload):
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

    total_tasks = int(file_list[-1].split("_")[1])

    print(f"Total number of tasks will be {total_tasks}")

    file_list = [tmp_dir.name + "/" + s for s in file_list]

    task_order_list = list()
    task_idx = 0
    task_order_list.append(task_idx)
    
    with PcapWriter(output_file, append=True, sync=True) as pktdump:
        with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 8)) as executor:
            for file in file_list:
                task_idx += 1
                executor.submit(parse_file_and_append, copy.deepcopy(file), file_lock, cv, copy.deepcopy(task_idx), task_order_list, pktdump, add_payload)

    tmp_dir.cleanup()

    return arr


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
