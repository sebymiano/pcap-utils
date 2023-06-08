# PCAP Tools
This folder contains a set of tools that can be used to manipulate large pcap files, or analyze them to extract useful information.

## Requirements
The tools are written in Python3, so you need to have it installed on your system.
We recommend using a virtual environment to install the dependencies, so that you don't mess up your system's Python installation.

### Virtual Environment
To create a virtual environment, run the following command:
```bash
python3 -m venv venv
```
This will create a folder called `venv` in the current directory, which will contain the virtual environment.
To activate the virtual environment, run the following command:
```bash
source venv/bin/activate
```

To deactivate the virtual environment, run the following command:
```bash
deactivate
```

### Dependencies
To install the dependencies, run the following command:
```bash
pip3 install -r requirements.txt
```

The scripts also require the `mergecap`, `editcap` and `capinfos` tools, which are part of the `wireshark` package.
You can install them using the following command:
```bash
sudo apt install wireshark-common
```

## Tools

### Trace preparation
There are different scripts in this folder that use different `engines` to process the traces, and save the results in different formats.
We recommend using the [`trace-preparation_panda`](./trace-preparation_panda.py) script, which uses the `scapy` engine to process the traces, and saves the results in a `pkl` file.

The information extracted from the traces is saved in a `pandas` DataFrame, which can be easily manipulated using the `pandas` library.
The list of fields extracted from the traces is shown in the table below.

|       **Field**      |               **Description**              |
|:--------------------:|:------------------------------------------:|
| tstamp               | Timestamp of the packet                    |
| pktsize              | Size of the packet                         |
| captured_size        | Size of the captured packet                |
| pkt_num              | Packet number                              |
| hdr.ethernet.src_mac | Source MAC address in Ethernet header      |
| hdr.ethernet.dst_mac | Destination MAC address in Ethernet header |
| hdr.ethernet.type    | Ethernet frame type                        |
| hdr.ipv4.src_addr    | Source IP address in IPv4 header           |
| hdr.ipv4.dst_addr    | Destination IP address in IPv4 header      |
| hdr.ipv4.ttl         | Time-to-Live (TTL) value in IPv4 header    |
| hdr.ipv4.protocol    | Protocol field in IPv4 header              |
| hdr.ipv4.checksum    | Checksum value in IPv4 header              |
| hdr.tcp.src_port     | Source port in TCP header                  |
| hdr.tcp.dst_port     | Destination port in TCP header             |
| hdr.tcp.checksum     | Checksum value in TCP header               |
| hdr.tcp.flags        | Flags in TCP header                        |
| hdr.tcp.seq          | Sequence number in TCP header              |
| hdr.tcp.ack          | Acknowledgment number in TCP header        |
| hdr.tcp.window       | Window size in TCP header                  |
| hdr.udp.src_port     | Source port in UDP header                  |
| hdr.udp.dst_port     | Destination port in UDP header             |
| hdr.udp.checksum     | Checksum value in UDP header               |
| hdr.udp.len          | Length of the UDP payload                  |

You can run the script using the following command:
```bash
python3 trace-preparation_panda.py -i <input_file> -o <output_file>
```

The script will start by splitting the input trace into multiple files. Then, it will process each file separately in parallel. Once the processing is done, the results of every process will be concatenated into a single Pandas DataFrame, which will be saved in the output file.

### Trace manipulation
There are different scripts in this folder that can be used to manipulate the traces.
We suggest to use the [`pcap-rewrite-scapy.py`](./pcap-rewrite-scapy.py) script, which uses the `scapy` engine to manipulate the traces.

You can modify the `modify_packet` function inside the script to change the way the packets are manipulated.
Even in this case, the script will split the input trace into multiple files, and process each file separately in parallel, generating multiple output files.
Then, it uses the `mergepcap` tool to merge the output files into a single trace.

You can run the script using the following command:
```bash
python3 pcap-rewrite-scapy.py -i <input_file> -o <output_file>
```