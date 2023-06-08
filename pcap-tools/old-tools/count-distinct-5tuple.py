import argparse
import numpy as np
from scapy.all import *
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]

def load_trace_npy(trace_name, use_mmap=True):
	if use_mmap:
		Trace=np.load(trace_name, mmap_mode='r')
	else:
		Trace=np.load(trace_name)
	return Trace


def count_distinct(trace):
    count = 0
    count_tcp = 0
    count_udp = 0
    # Create a different array with only the 5-tuple
    max_size = trace.size
    print(f"The entire size of the trace is {max_size}")
    pbar = ProgressBar(widgets=widgets, maxval=max_size).start()
    final_list = dict()
    for entry in trace:
        count += 1
        pbar.update(count)

        new_entry = list()

        # Source IP
        new_entry.append(entry[1])
        # Destination IP
        new_entry.append(entry[2])
        # Protocol
        new_entry.append(entry[4])

        if new_entry[2] == socket.IPPROTO_TCP:
            count_tcp += 1
            # TCP Src Port
            new_entry.append(entry[6])
            # TCP Dst Port
            new_entry.append(entry[7])
        elif new_entry[2] == socket.IPPROTO_UDP:
            count_udp += 1
            # UDP Src Port
            new_entry.append(entry[9])
            # UDP Dst Port
            new_entry.append(entry[10])
        else:
            continue

        new_entry_tuple = tuple(new_entry)
        if new_entry_tuple in final_list:
            final_list[new_entry_tuple] += 1
        else:
            final_list[new_entry_tuple] = 1

    # final_list.append(tuple(new_entry))
    # arr=np.zeros((len(final_list)),dtype=np.dtype('u4,u4,u2,u2,u2'))

    # for i in range(len(final_list)):
    #     arr[i]=final_list[i]

    print(f"Counted {count_tcp} TCP packets and {count_udp} UDP packets")

    return len(final_list)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to count the distinct 5tuple in a PCAP trace')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="Filename for input numpy file")
    parser.add_argument("-o", "--output-file", required=True, type=str, help="Filename for output parsed numpy file (for efficient loading)")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_path = args.output_file

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    trace = load_trace_npy(input_file_path)

    distinct_5tuple = count_distinct(trace)

    with open(output_file_path, "w") as output:
        output.writelines(f"Number of distinct 5tuple in the trace {input_file_path}: {distinct_5tuple}")