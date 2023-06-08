# BPF PCAP Tools
This repository contains a set of tools that use the results of the analysis of a pcap file to interact with BPF programs using a wrapper to the [libbpf](./libbpf.py) library and the [libcuckoo](https://github.com/sebymiano/cuckoo_hash_bpf/tree/main) library.

## Requirements
Before using the tools, you need to compile the shared libraries that will be loaded at runtime by the Python scripts.

To do so, go inside the `libcuckoo-bpf` folder and run the following commands:

```bash
$ git submodule update --init --recursive
$ make -C src all
```

## libcuckoo.py
This script is used to interact with the BPF program that uses the [libcuckoo](https://github.com/sebymiano/cuckoo_hash_bpf/tree/main) library.

Inside the python script, you can instantiate the `Libcuckoo` class that will load the shared library and will allow you to interact with the BPF program.

```python
import libcuckoo

cuckoo_api = libcuckoo.Libcuckoo(libcuckoo_path, libbpf_path)
```

The `libcuckoo_path` and `libbpf_path` parameters are the paths to the shared libraries that you compiled before.
The `test-flow.py` script contains an example of how to use the `Libcuckoo` class.


