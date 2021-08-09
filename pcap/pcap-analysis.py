import argparse
import collections
import csv
import os
import pickle
import socket
import subprocess

from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]

protoTable = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}


class Integer(object):
    def __init__(self, val=0):
        self._val = int(val)

    def __add__(self, val):
        if isinstance(val, Integer):
            return Integer(self._val + val._val)
        return self._val + val

    def __iadd__(self, val):
        self._val += val
        return self

    def __str__(self):
        return str(self._val)

    def __repr__(self):
        return 'Integer(%s)' % self._val


SrcIPs = dict()
DstIPs = dict()
Protocols = dict()
SrcPort = dict()
DstPort = dict()
Flows = dict()
totLines = dict()
GeneralInfo = dict()


def save_obj(obj, name):
    with open('obj/' + name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    with open('obj/' + name + '.pkl', 'rb') as f:
        return pickle.load(f)


def parse_pkt(packet):
    totLines[0] += 1
    skip_layer = True

    if not GeneralInfo["TotPackets"]:
        GeneralInfo["TotPackets"] = 1
    else:
        GeneralInfo["TotPackets"] += 1

    if not GeneralInfo["TotPacketsSize"]:
        GeneralInfo["TotPacketsSize"] = packet.wirelen
    else:
        GeneralInfo["TotPacketsSize"] += packet.wirelen

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    if TCP in packet[IP]:
        layer = packet.getlayer(TCP)
        skip_layer = False
    elif UDP in packet[IP]:
        layer = packet.getlayer(UDP)
        skip_layer = False

    if src_ip not in SrcIPs:
        SrcIPs[src_ip] = 1
    else:
        SrcIPs[src_ip] += 1

    if dst_ip not in DstIPs:
        DstIPs[dst_ip] = 1
    else:
        DstIPs[dst_ip] += 1

    if proto not in Protocols:
        Protocols[proto] = 1
    else:
        Protocols[proto] += 1

    if not skip_layer:
        src_port = layer.sport
        dst_port = layer.dport

        if src_port not in SrcPort:
            SrcPort[src_port] = 1
        else:
            SrcPort[src_port] += 1

        if dst_port not in DstPort:
            DstPort[dst_port] = 1
        else:
            DstPort[dst_port] += 1

        flow = (src_ip, dst_ip, proto, src_port, dst_port)
    else:
        flow = (src_ip, dst_ip, proto)

    if flow not in Flows:
        Flows[flow] = 1
    else:
        Flows[flow] += 1

    pbar.update(totLines[0])

def save_general_info_dict():
    flow_output_file_path = os.path.join(output_file_dir, f"general_info.csv")
    with open(flow_output_file_path, 'w') as csv_output_file:
        fieldnames = ['Tot Packets', 'Tot Size', 'Avg Pkt Size']

        writer = csv.DictWriter(csv_output_file, fieldnames=fieldnames)
        writer.writeheader()

        writer.writerow({'Tot Packets': str(GeneralInfo["TotPackets"]), 'Tot Size': str(GeneralInfo["TotPacketsSize"]), 'Proto': str(GeneralInfo["TotPacketsSize"]/GeneralInfo["TotPackets"])})


def save_flow_dict():
    flow_output_file_path = os.path.join(output_file_dir, f"flows.csv")
    most_used_flow = None
    count = 0

    if sort_dict:
        new_dict = collections.OrderedDict(sorted(Flows.items(), key=lambda item: item[1], reverse=True))
    else:
        new_dict = Flows

    with open(flow_output_file_path, 'w') as csv_output_file:
        fieldnames = ['Source IP', 'Dst IP', 'Proto', 'Src Port', 'Dst Port', 'Count', 'Percentage']
        writer = csv.DictWriter(csv_output_file, fieldnames=fieldnames)
        writer.writeheader()
        for k, v in new_dict.items():
            if v > count:
                most_used_flow = k
                count = v

            percentage = float(v) / float(totLineOriginalFile)
            if len(k) == 5:
                writer.writerow({'Source IP': str(k[0]), 'Dst IP': str(k[1]), 'Proto': str(k[2]), 'Src Port': str(k[3]),
                                 'Dst Port': str(k[4]), 'Count': str(v), 'Percentage': str(percentage)})
            elif len(k) == 3:
                writer.writerow({'Source IP': str(k[0]), 'Dst IP': str(k[1]), 'Proto': str(k[2]), 'Count': str(v),
                                 'Percentage': str(percentage)})
            else:
                assert False, "Wrong number of parameters into flow tuples"

    if not detailed:
        return

    print(f"There are a total of {len(new_dict.items())} distinct flows in the pcap trace")
    print(f"The most used flow is the following, with a total of {count} packets over {totLineOriginalFile}")
    flow = most_used_flow
    if len(flow) == 5:
        print(f"Source IP: {str(flow[0])}, Dst IP: {str(k[1])}, Proto: {str(k[2])}, Src Port: {str(k[3])}, "
              f"DstPort: {str(k[4])}")
    else:
        print(f"Source IP: {str(flow[0])}, Dst IP: {str(k[1])}, Proto: {str(k[2])}")
    print("\n")


def save_dict(dictionary, dict_type):
    dictionary_output_file_path = os.path.join(output_file_dir, f"{dict_type.lower().replace(' ', '_')}.csv")
    most_used = None
    count = 0

    if sort_dict:
        new_dict = collections.OrderedDict(sorted(dictionary.items(), key=lambda item: item[1], reverse=True))
    else:
        new_dict = dictionary

    with open(dictionary_output_file_path, 'w') as csv_output_file:
        fieldnames = [dict_type, 'Count', 'Percentage']
        writer = csv.DictWriter(csv_output_file, fieldnames=fieldnames)
        writer.writeheader()
        for k, v in new_dict.items():
            if v > count:
                most_used = k
                count = v

            percentage = float(v) / float(totLineOriginalFile)
            writer.writerow({dict_type: str(k), 'Count': str(v), 'Percentage': str(percentage)})

    if not detailed:
        return

    print(f"There are a total of {len(new_dict.items())} distinct {dict_type} in the pcap trace")
    print(f"The most used {dict_type} is the following, with a total of {count} packets over {totLineOriginalFile}")

    print(f"{dict_type}: {str(most_used)}")
    print("\n")


def parse_and_write_file(input_file):
    # packets = rdpcap(input_file)
    sniff(offline=input_file, prn=parse_pkt, store=0)
    print("\n")
    save_flow_dict()
    save_general_info_dict()
    save_dict(SrcIPs, "Source IPs")
    save_dict(DstIPs, "Destination IPs")
    save_dict(Protocols, "Protocols")
    save_dict(SrcPort, "Source Ports")
    save_dict(DstPort, "Destination Ports")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to analyze PCAP traces')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="The PCAP input file")
    parser.add_argument("-o", "--output-dir", required=True, type=str,
                        help="The output directory")
    parser.add_argument("-d", "--detailed", dest='detailed', action='store_true', default=False,
                        help="Print additional statistics on command line")
    parser.add_argument("-s", "--sorted", dest='sort_dict', action='store_true', default=False,
                        help="Sort results in decreasing order")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_dir = args.output_dir
    detailed = args.detailed
    sort_dict = args.sort_dict

    if not os.path.isdir(output_file_dir):
        print("Error! The output file should be a directory")
        exit(1)

    cmd = f"/usr/bin/tshark -r {input_file_path}"
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    totLineOriginalFile = subprocess.check_output(('wc', '-l'), stdin=ps.stdout)
    ps.wait()
    totLineOriginalFile = int(totLineOriginalFile)
    # subprocess.run(["ls", "-l"])
    pbar = ProgressBar(widgets=widgets, maxval=totLineOriginalFile).start()
    totLines[0] = 0
    parse_and_write_file(input_file_path)

    exit(0)
