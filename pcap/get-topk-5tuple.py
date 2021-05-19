import argparse
import numpy as np
import heapq
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

def dottedQuadToNum(ip):
    #"convert decimal dotted quad string to long integer"
    return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
	#"convert long int to dotted quad string"
	return socket.inet_ntoa(struct.pack('>L',n))

def count_topk(trace, top_k):
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

    print("\n\n")
    print(f"Counted {count_tcp} TCP packets and {count_udp} UDP packets")
    
    heap = []
    count = 0
    for key, v in final_list.items():
        count += 1
        heapq.heappush(heap, (v, count, key))

    topk_list = heapq.nlargest(top_k, heap)

    return topk_list

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to count the distinct 5tuple in a PCAP trace')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="Filename for input numpy file")
    parser.add_argument("-k", "--top-k", default=32, type=int, help="Number of TOP K Flows to get")
    parser.add_argument("-o", "--output-file", required=True, type=str, help="Filename for output parsed numpy file (for efficient loading)")

    args = parser.parse_args()

    input_file_path = args.input_file
    output_file_path = args.output_file

    try:
        os.remove(output_file_path)
    except OSError:
        pass

    trace = load_trace_npy(input_file_path)

    topk_list = count_topk(trace, args.top_k)

    with open(output_file_path, "w") as output:
        output.writelines(f"The Top-{args.top_k} items on the trace {input_file_path} are the following")
        output.write("\n")
        for entry in topk_list:
            new_entry_list = list(entry[2])
            new_entry_list[0] = numToDottedQuad(entry[2][0])
            new_entry_list[1] = numToDottedQuad(entry[2][1])
            output.writelines(f"5 Tuple: {tuple(new_entry_list)} - Value: {entry[0]}")
            output.write("\n\n")