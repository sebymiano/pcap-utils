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

import libcuckoo

# Define the structure
class FlowKey(ctypes.Structure):
    #_pack_ = 1
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8)
    ]
    
# Create an array of struct flow_key
keys = [
    FlowKey(0x10101010, 0x10101011, 1, 2, 17),
    FlowKey(0x10101010, 0x10101013, 2, 1, 17),
    FlowKey(0x10101010, 0x10101014, 10, 10, 30),
    FlowKey(0x10101010, 0x10101014, 1, 22, 30),
    FlowKey(0x10101010, 0x10101014, 15, 10, 50),
    FlowKey(0x10101010, 0x10101014, 10, 20, 70),
    FlowKey(0x10101010, 0x10101014, 10, 7, 50),
    FlowKey(0x10101010, 0x10101014, 2, 3, 100),
    FlowKey(0x10101010, 0x10101014, 1, 1, 1),
    FlowKey(0x10101010, 0x10101014, 3, 3, 30),
    FlowKey(0x10101010, 0x10101014, 4, 5, 30),
]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used test the API of the libcuckoo library')
    parser.add_argument("--map_id", "-m", dest="map_id", help="BPF Map ID", required=True)
    parser.add_argument("--libcuckoo_path", "-l", dest="libcuckoo_path", help="Path to libcuckoo.so")
    parser.add_argument("--libbpf_path", "-b", dest="libbpf_path", help="Path to libbpf.so")
    
    args = parser.parse_args()

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

    cuckoo_api = libcuckoo.Libcuckoo(args.libcuckoo_path, args.libbpf_path)
    cuckoo_map = cuckoo_api.init_by_id(ctypes.c_int(int(args.map_id)), ctypes.sizeof(FlowKey), ctypes.sizeof(ctypes.c_uint32), ctypes.c_uint32(512))

    try:
        for j in atpbar(range(len(keys)), name=f"Keys Insertion"):
            flow = keys[j]
            value = ctypes.c_uint32(flow.protocol)
            cuckoo_api.insert(cuckoo_map, ctypes.byref(flow), ctypes.byref(value), ctypes.sizeof(FlowKey), ctypes.sizeof(ctypes.c_uint32))
    except Exception as e:
        print(f"Exception: {e}")
        cuckoo_api.destroy(cuckoo_map)
        exit(1)

    cuckoo_api.destroy(cuckoo_map)



