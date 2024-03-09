import re
import argparse
import socket
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA


protoTable = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}

srcIP = r'(?P<SrcIp>(?:(?:\d){1,3}\.){3}(?:\d){1,3})\/(?P<SrcNm>(?:\d){1,3})'
dstIP = r'(?P<DstIp>(?:(?:\d){1,3}\.){3}(?:\d){1,3})\/(?P<DstNm>(?:\d){1,3})'
srcPort = r'(?P<SrcPortStart>\d{1,5})(?:\s+):(?:\s+)(?P<SrcPortEnd>\d{1,5})'
dstPort = r'(?P<DstPortStart>\d{1,5})(?:\s+):(?:\s+)(?P<DstPortEnd>\d{1,5})'
IPproto = r'(?:0x)(?P<Proto>[0-9a-fA-F]{1,2})\/(?:0x)(?P<ProtoMask>[0-9a-fA-F]{1,2})'
tcpFlags = r'(?:0x)(?P<TCPFlags>[0-9a-fA-F]{4})\/(?:0x)(?P<TCPFlagsMask>[0-9a-fA-F]{4})'

finalString = fr'@{srcIP}(?:\s+){dstIP}(?:\s+){srcPort}(?:\s+){dstPort}(?:\s+){IPproto}(?:\s+){tcpFlags}'
finalRegex = re.compile(finalString)

widgets = [Percentage(),
           ' ', Bar(),
           ' ', ETA(),
           ' ', AdaptiveETA()]


def parse_line(line):
    match = finalRegex.search(line)
    return match


def get_src_ip_string(src_ip, src_netmask):
    if src_ip == "0.0.0.0":
        return ""

    src_cmd = " ip saddr "

    if int(src_netmask) == 32:
        return f"{src_cmd}{src_ip}"
    else:
        return f"{src_cmd}{src_ip}/{src_netmask}"


def get_dst_ip_string(dst_ip, dst_netmask):
    if dst_ip == "0.0.0.0":
        return ""

    dst_cmd = " ip daddr "    

    if int(dst_netmask) == 32:
        return f"{dst_cmd}{dst_ip}"
    else:
        return f"{dst_cmd}{dst_ip}/{dst_netmask}"


def get_port_string(start, end, proto_str, port_cmd):
    start_port = int(start)
    end_port = int(end)
    port_str = ""
    assert (start_port <= 65535 and end_port <= 65535), "Source ports are not correctly formatted"
    if start_port == 0 and end_port == 65535:
        return port_str

    if start_port == end_port:
        return fr"{proto_str}{port_cmd}{start_port} "

    if not expandRange:
        return fr"{proto_str}{port_cmd}{start_port}-{end_port} "
    else:
        while start_port <= end_port:
            port_str += fr"{proto_str}{port_cmd}{start_port} "
            start_port += 1

    return port_str


def get_src_port_string(start, end, proto_str):

    src_port_cmd = " sport "   
    return get_port_string(start, end, proto_str, src_port_cmd) 


def get_dst_port_string(start, end, proto_str):

    dst_port_cmd = " dport "   
    return get_port_string(start, end, proto_str, dst_port_cmd) 


def get_proto_string(proto, proto_mask):
    proto = int(proto, 16)
    proto_mask = int(proto_mask, 16)
    proto_str = ""
    skip_port = False

    if proto == 0:
        return True, proto_str

    if proto not in protoTable:
        print(f'Unrecognized protocol {proto}')
        return True, proto_str

    if proto_mask == int("FF", 16):
        if proto == 1:
            skip_port = True

        proto_str = fr" {protoTable[proto]}".lower()
        return skip_port, proto_str

    return skip_port, proto_str


def parse_and_write_file(input_file, output_file):
    input_lines = 0
    output_lines = 0
    with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
        output_file.write(f"add table {nft_table}\n")
        output_file.write(f"add chain {nft_table} {nft_chain} {{ type filter hook {nft_hook} priority 0; }}\n")
        maxlines = sum(1 for _ in input_file)
        input_file.seek(0)
        pbar = ProgressBar(widgets=widgets, maxval=maxlines).start()
        line = input_file.readline()

        while line:
            input_lines += 1
            pbar.update(input_lines)

            string_list = f"add rule ip {nft_table} {nft_chain}"
            # at each line check for a match with a regex
            match = parse_line(line)
            assert match, f"The file is not in the expected format in line {input_lines}!"

            src_ip = match.group('SrcIp')
            src_netmask = match.group('SrcNm')
            dst_ip = match.group('DstIp')
            dst_netmask = match.group('DstNm')
            src_port_start = match.group('SrcPortStart')
            src_port_end = match.group('SrcPortEnd')
            dst_port_start = match.group('DstPortStart')
            dst_port_end = match.group('DstPortEnd')
            proto = match.group('Proto')
            proto_mask = match.group('ProtoMask')
            tcp_flags = match.group('TCPFlags')
            tcp_flags_mask = match.group('TCPFlagsMask')

            string_list += get_src_ip_string(src_ip, src_netmask)
            string_list += get_dst_ip_string(dst_ip, dst_netmask)

            skip_port = False
            proto_str = ""
            add_proto = True
            skip_port, proto_res = get_proto_string(proto, proto_mask)
            print(skip_port, proto_res)
            if len(proto_res) > 0:
                proto_str = proto_res

            if not skip_port:
                src_port_res = get_src_port_string(src_port_start, src_port_end, proto_str)
                if len(src_port_res) > 0:
                    string_list += src_port_res
                    add_proto = False

                dst_port_res = get_dst_port_string(dst_port_start, dst_port_end, proto_str)
                if len(dst_port_res) > 0:
                    string_list += dst_port_res
                    add_proto = False

            
            if add_proto:
                if proto_str != "":
                    string_list += fr" ip protocol{proto_str} "

            string_list += fr"counter {defaultAction}"

            output_file.write(string_list+"\n")
            output_lines += 1

            line = input_file.readline()

    return input_lines, output_lines


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to convert Classbench rules into nf_table rules.')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="The Classbench input file")
    parser.add_argument("-o", "--output-file", required=True, type=str,
                        help="The output file where to same the ruleset")
    parser.add_argument("-t", "--table", default="filer", type=str,
                        help="The name of the table")
    parser.add_argument("-c", "--chain", default="INPUT", type=str,
                        help="The name of the chain")
    parser.add_argument("-p", "--hook", choices=["ingress", "prerouting", "input", "forward", "output", "postrouting"], default="prerouting", type=str,
                        help="The chain where to append the rules")
    parser.add_argument("-e", "--expand-range", type=bool, default=False,
                        help="Create a separate rule for each port range value")
    parser.add_argument("-j", "--default-action", choices=["accept", "drop"], type=str, default="accept",
                        help="Default action to use in the rule")

    args = parser.parse_args()

    nft_table = args.table
    nft_chain = args.chain
    nft_hook = args.hook
    input_file_path = args.input_file
    output_file_path = args.output_file
    expandRange = args.expand_range
    defaultAction = args.default_action

    tot_input_lines, tot_output_lines = parse_and_write_file(input_file_path, output_file_path)

    print(f"Read and parsed a total of {tot_input_lines} from file and wrote {tot_output_lines} lines")
    print(f"Output file created: {output_file_path}")
