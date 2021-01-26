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

    if iptablesBinary == "polycubectl":
        src_cmd = " src="
    else:
        src_cmd = " -s "

    if int(src_netmask) == 32:
        return f"{src_cmd}{src_ip}"
    else:
        return f"{src_cmd}{src_ip}/{src_netmask}"


def get_dst_ip_string(dst_ip, dst_netmask):
    if dst_ip == "0.0.0.0":
        return ""

    if iptablesBinary == "polycubectl":
        dst_cmd = " dst="
    else:
        dst_cmd = " -d "    

    if int(dst_netmask) == 32:
        return f"{dst_cmd}{dst_ip}"
    else:
        return f"{dst_cmd}{dst_ip}/{dst_netmask}"


def get_src_port_string(start, end, start_string):
    start_port = int(start)
    end_port = int(end)
    port_list = list()
    assert (start_port <= 65535 and end_port <= 65535), "Source ports are not correctly formatted"

    if iptablesBinary == "polycubectl":
        src_port_cmd = " sport="
    else:
        src_port_cmd = " --sport "   

    if start_port == 0 and end_port == 65535:
        return port_list
    if start_port == end_port:
        port_list.append(start_string + fr"{src_port_cmd}{start_port}:{start_port}")
        return port_list

    if not expandRange:
        port_list.append(start_string + fr"{src_port_cmd}{start_port}:{end_port}")
        return port_list
    else:
        while start_port <= end_port:
            port_list.append(start_string + fr"{src_port_cmd}{start_port}:{start_port}")
            start_port += 1

    return port_list


def get_dst_port_string(start, end, start_string):
    start_port = int(start)
    end_port = int(end)
    port_list = list()
    assert (start_port <= 65535 and end_port <= 65535), "Destination ports are not correctly formatted"

    if iptablesBinary == "polycubectl":
        dst_port_cmd = " dport="
    else:
        dst_port_cmd = " --dport "   

    if start_port == 0 and end_port == 65535:
        return port_list
    if start_port == end_port:
        port_list.append(start_string + fr"{dst_port_cmd}{start_port}:{start_port}")
        return port_list

    if not expandRange:
        port_list.append(start_string + fr"{dst_port_cmd}{start_port}:{end_port}")
        return port_list
    else:
        while start_port <= end_port:
            port_list.append(start_string + fr"{dst_port_cmd}{start_port}:{start_port}")
            start_port += 1

    return port_list


def get_proto_string(proto, proto_mask, start_str):
    proto = int(proto, 16)
    proto_mask = int(proto_mask, 16)
    proto_list = list()
    skip_port = False

    if proto == 0:
        return True, proto_list

    if proto not in protoTable:
        print(f'Unrecognized protocol {proto}')
        return True, proto_list

    if iptablesBinary == "polycubectl":
        proto_cmd = " l4proto="
    else:
        proto_cmd = " -p "  

    if proto_mask == int("FF", 16):
        if proto == 1:
            skip_port = True

        proto_list.append(start_str + fr"{proto_cmd}{protoTable[proto]}")
        return skip_port, proto_list

    return skip_port, proto_list


def parse_and_write_file(input_file, output_file):
    input_lines = 0
    output_lines = 0
    with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
        maxlines = sum(1 for _ in input_file)
        input_file.seek(0)
        pbar = ProgressBar(widgets=widgets, maxval=maxlines).start()
        line = input_file.readline()
        while line:
            input_lines += 1
            pbar.update(input_lines)
            string_list = list()

            if iptablesBinary == "polycubectl":
                pcn_iptables_string = fr'{iptablesBinary} pcn-iptables chain {defaultChain} append'
                action_cmd = fr' action='
            else:
                pcn_iptables_string = fr'{iptablesBinary} -A {defaultChain}'
                action_cmd = fr' -j '

            string_list.append(pcn_iptables_string)
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

            string_list = [s + get_src_ip_string(src_ip, src_netmask) for s in string_list]
            string_list = [s + get_dst_ip_string(dst_ip, dst_netmask) for s in string_list]

            skip_port = False
            for start_str in string_list:
                skip_port, proto_res = get_proto_string(proto, proto_mask, start_str)
                if len(proto_res) > 0:
                    string_list = proto_res

            if not skip_port:
                for start_str in string_list:
                    src_port_res = get_src_port_string(src_port_start, src_port_end, start_str)
                    if len(src_port_res) > 0:
                        string_list = src_port_res

                for start_str in string_list:
                    dst_port_res = get_dst_port_string(dst_port_start, dst_port_end, start_str)
                    if len(dst_port_res) > 0:
                        string_list = dst_port_res

            string_list = [s + fr"{action_cmd}{defaultAction}" for s in string_list]

            for item in string_list:
                output_file.write("%s\n" % item)
                output_lines += 1

            line = input_file.readline()

    return input_lines, output_lines


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Program used to convert Classbench rules into pcn/iptables rules')
    parser.add_argument("-i", "--input-file", required=True, type=str, help="The Classbench input file")
    parser.add_argument("-o", "--output-file", required=True, type=str,
                        help="The output file where to same the ruleset")
    parser.add_argument("-n", "--name", choices=["iptables", "pcn-iptables", "polycubectl"], default="pcn-iptables", type=str,
                        help="The name of the program to use")
    parser.add_argument("-c", "--chain", choices=["INPUT", "FORWARD", "OUTPUT"], default="FORWARD", type=str,
                        help="The chain where to append the rules")
    parser.add_argument("-e", "--expand-range", type=bool, default=False,
                        help="Create a separate rule for each port range value")
    parser.add_argument("-j", "--default-action", choices=["ACCEPT", "DROP"], type=str, default="ACCEPT",
                        help="Default action to use in the rule")

    args = parser.parse_args()

    iptablesBinary = args.name
    defaultChain = args.chain
    input_file_path = args.input_file
    output_file_path = args.output_file
    expandRange = args.expand_range
    defaultAction = args.default_action

    tot_input_lines, tot_output_lines = parse_and_write_file(input_file_path, output_file_path)

    print(f"Read and parsed a total of {tot_input_lines} from file and wrote {tot_output_lines} lines")
    print(f"Output file created: {output_file_path}")
