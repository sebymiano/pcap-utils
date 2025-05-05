import argparse
import os
import random
import shutil
import subprocess
import pypacker
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp
import progressbar


def generate_payload(length, random_payload):
    return os.urandom(length) if random_payload else bytes(length)


def generate_random_mac():
    return bytes(random.randint(0x00, 0xFF) for _ in range(6))


def add_payload_to_packet(pkt_bytes, random_payload):
    try:
        eth = ethernet.Ethernet()          
        eth.src = generate_random_mac()
        eth.dst = generate_random_mac()
        eth.type = ethernet.ETH_TYPE_IP
        
        ip_layer = ip.IP(pkt_bytes)
        eth.upper_layer = ip_layer

        # Only support IPv4
        if not isinstance(ip_layer, ip.IP):
            return None
        
        if ip_layer[tcp.TCP] is not None or ip_layer[udp.UDP] is not None:
            l4 = ip_layer[tcp.TCP] if ip_layer[tcp.TCP] else ip_layer[udp.UDP]
        else:
            return None

        ip_len = ip_layer.len if ip_layer.len is not None else len(pkt_bytes)
        ip_header_len = ip_layer.hl * 4
        if isinstance(l4, tcp.TCP):
            l4_header_len = l4.off * 4
        elif isinstance(l4, udp.UDP):
            l4_header_len = 8
        else:
            print("Unsupported layer 4 protocol. Only TCP and UDP are supported.")
            return None


        original_payload_len = ip_len - ip_header_len - l4_header_len
        # print(f"Payload length: {original_payload_len}")

        if original_payload_len < 0:
            print("Error: Packet too small to add payload.")
            return None

        l4.body_bytes = generate_payload(original_payload_len, random_payload)

        # Reset checksums and lengths
        ip_layer.len = None
        ip_layer.sum = None
        l4.sum = None
        eth.upper_layer = ip_layer
        ip_layer.upper_layer = l4

        # print(eth)

        return eth.bin()

    except Exception:
        # print(f"Error processing packet: {e}")
        return None


def get_total_packets(file_name):
    try:
        command = (
            f'capinfos {file_name} | grep "Number of packets" | tr -d " " | grep -oP "Numberofpackets=\\K\\d+"'
        )
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        return int(output.strip())
    except Exception as e:
        print(f"Failed to get packet count with capinfos: {e}")
        return None


def convert_to_pcapng(pcap_path, pcapng_path):
    if not shutil.which("editcap"):
        print("Error: 'editcap' not found in PATH. Install Wireshark CLI tools.")
        return False

    try:
        subprocess.run(["editcap", "-F", "pcapng", pcap_path, pcapng_path], check=True)
        print(f"Converted {pcap_path} to {pcapng_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"editcap failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Add payload to pcap packets.")
    parser.add_argument("-i", "--input-pcap", required=True, type=str, help="Filename for input PCAP")
    parser.add_argument("-o", "--output-pcap", required=True, type=str, help="Filename for output PCAP")
    parser.add_argument("-r", "--random", action="store_true", help="Use random payload instead of zeroes")
    parser.add_argument("--pcapng", action="store_true", help="Convert final output to pcapng format")
    args = parser.parse_args()

    if not os.path.isfile(args.input_pcap):
        print(f"Input file {args.input_pcap} does not exist.")
        return

    total_packets = get_total_packets(args.input_pcap)
    # total_packets = 1000
    if total_packets is None:
        print("Could not determine packet count. Proceeding without progress bar.")
        total_packets = 0

    reader = ppcap.Reader(filename=args.input_pcap)
    writer = ppcap.Writer(filename=args.output_pcap)

    widgets = [
        "Processing: ",
        progressbar.Percentage(),
        " ",
        progressbar.Bar(marker="=", left="[", right="]"),
        " ",
        progressbar.ETA(),
    ]
    bar = progressbar.ProgressBar(widgets=widgets, max_value=total_packets or progressbar.UnknownLength)

    counter = 0
    for ts, buf in reader:
        modified_pkt = add_payload_to_packet(buf, args.random)
        if modified_pkt:
            writer.write(modified_pkt, ts=ts)
        counter += 1
        bar.update(counter)
    bar.finish()
    print(f"\nProcessed {counter} packets.")

    reader.close()
    writer.close()
    print(f"\nModified PCAP written to {args.output_pcap}")

    if args.pcapng:
        pcapng_path = os.path.splitext(args.output_pcap)[0] + ".pcapng"
        convert_to_pcapng(args.output_pcap, pcapng_path)


if __name__ == "__main__":
    main()
