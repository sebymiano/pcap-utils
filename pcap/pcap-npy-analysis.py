import argparse
import numpy as np
import heapq
from scapy.all import *
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
from enum import Enum

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]

class DistinctField(Enum):
    srcIP = 'srcip'
    dstIP = 'dstip'
    proto = 'proto'
    srcPort = 'srcport'
    dstPort = 'dstport'

    def __str__(self):
        return self.value


def load_trace_npy(trace_name, use_mmap=True):
	if use_mmap:
		Trace=np.load(trace_name, mmap_mode='r')
	else:
		Trace=np.load(trace_name)
	return Trace

def dottedQuadToNum(ip):
    #"convert decimal dotted quad string to long integer"
    return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
	#"convert long int to dotted quad string"
	return socket.inet_ntoa(struct.pack('>L',n))

def parse_and_write_field(trace, output_file, field_num, field_name):
    count = 0
    # Create a different array with only the 5-tuple
    max_size = trace.size
    print(f"The entire size of the trace is {max_size}")
    pbar = ProgressBar(widgets=widgets, maxval=max_size).start()
    final_list = set()
    for entry in trace:
        count += 1
        pbar.update(count)

        final_list.add(entry[field_num])

    print("\n\n")
    
    with open(output_file, "w") as output:
        output.writelines(f"Found {len(final_list)} distinct {field_name} in the trace")
        output.write("\n")
        for entry in final_list:
            output.writelines(f"{numToDottedQuad(entry)}\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to count the distinct 5tuple in a PCAP trace')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="Filename for input numpy file")
    parser.add_argument("-d", "--distinct", required=True, type=DistinctField, choices=list(DistinctField))
    parser.add_argument("-o", "--output-file", required=True, type=str, help="Filename for output parsed numpy file (for efficient loading)")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_path = args.output_file

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    trace = load_trace_npy(input_file_path)

    if args.distinct == DistinctField.srcIP:
        parse_and_write_field(trace, output_file_path, 1, args.distinct)
    elif args.distinct == DistinctField.dstIP:
        parse_and_write_field(trace, output_file_path, 2, args.distinct)
    elif args.distinct == DistinctField.proto:
        parse_and_write_field(trace, output_file_path, 4, args.distinct)
    else:
        print(f"The field {args.distinct} is not currently supported")

