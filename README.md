# PCAP Utils
This repository contains a set of tools that can be used to *manipulate* **large** pcap files, *analyze* them to extract useful information, *convert* them to other formats, and *generate synthetic traces* from `Classbench`, a packet classification tool that generates ACLs and traffic patterns based on different distributions.

There are three main folders in this repository:
1. [`pcap-tools`](./pcap-tools/): Contains a set of tools that can be used to manipulate large pcap files, or analyze them to extract useful information.
2. [`bpf-pcap-tools`](./bpf-pcap-tools/): Contains a set of tools that use the results of the analysis of a pcap file to interact with BPF programs using a wrapper to the [libbpf](./libbpf.py) library and the [libcuckoo](https://github.com/sebymiano/cuckoo_hash_bpf/tree/main) library.
3. [`classbench-tools`](./classbench-tools/): Contains a set of tools that can be used to generate traces from `Classbench`, a packet classification tool that generates ACLs and traffic patterns based on different distributions.
