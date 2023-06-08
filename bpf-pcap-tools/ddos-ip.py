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

import libbpf
import libcuckoo

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('>L',n))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to read unique IP addresses from a pkl file and write them to a BPF cuckoo hash map')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--map_id", "-m", dest="map_id", help="BPF Map ID", required=True)
    parser.add_argument("--libcuckoo_path", "-l", dest="libcuckoo_path", help="Path to libcuckoo.so")
    parser.add_argument("--libbpf_path", "-b", dest="libbpf_path", help="Path to libbpf.so")
    
    args = parser.parse_args()

    # Check if the input file exists
    if not os.path.exists(args.input_file):
        print(f"Input file {args.input_file} does not exist")
        exit(1)

    # Get the script path
    script_path = os.path.realpath(__file__) 
    # Get the script directory
    script_dir = os.path.dirname(script_path) 

    if not args.libcuckoo_path:
        args.libcuckoo_path = os.path.join(script_dir, "libcuckoo-bpf", "src", ".output", "libcuckoo.so")
        print(f"libcuckoo_path not specified, using the default one: {args.libcuckoo_path}")
    elif not os.path.exists(args.libcuckoo_path):
        print(f"libcuckoo_path does not exist: {args.libcuckoo_path}")
        exit(1)

    if not args.libbpf_path:
        args.libbpf_path = os.path.join(script_dir, "libcuckoo-bpf", "src", ".output", "libbpf.so")
        print(f"libbpf_path not specified, using the default one: {args.libbpf_path}")
    elif not os.path.exists(args.libcuckoo_path):
        print(f"libbpf_path does not exist: {args.libcuckoo_path}")
        exit(1)

    data_frame = pd.read_pickle(args.input_file)

    print(f"Input file {args.input_file} read successfully")

    # Get unique values from the src ip column
    unique_src_ips = data_frame['hdr.ipv4.src_addr'].unique().tolist()

    print(f"Number of unique source IPs: {len(unique_src_ips)}")

    cuckoo_api = libcuckoo.Libcuckoo(args.libcuckoo_path, args.libbpf_path)

    cuckoo_map = cuckoo_api.init_by_id(ctypes.c_int(int(args.map_id)), ctypes.sizeof(ctypes.c_uint32), ctypes.sizeof(ctypes.c_uint32), ctypes.c_uint32(512))

    try:
        for j in atpbar(range(len(unique_src_ips)), name=f"IP Insertion"):
            ip_val = int(unique_src_ips[j])
            # print(numToDottedQuad(ip_val))
            ip_int = ctypes.c_uint32(ip_val)
            value = ctypes.c_uint32(0)
            cuckoo_api.insert(cuckoo_map, ctypes.byref(ip_int), ctypes.byref(value), ctypes.sizeof(ctypes.c_uint32), ctypes.sizeof(ctypes.c_uint32))
    except Exception as e:
        print(f"Exception: {e}")
        cuckoo_api.destroy(cuckoo_map)
        exit(1)

    cuckoo_api.destroy(cuckoo_map)



