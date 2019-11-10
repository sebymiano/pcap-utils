# classbench-to-iptables
Convert classbench rules to bpf/-iptables counterparts

This repository contains a simple Python script that can be used to convert automatically generated Classbench rules into a set of rules that can be loaded in either `iptables` or `bpf-iptables`.

## Usage

To use the script you can simply update the global variables at the start of the file.
Within the current behaviour, source and destination ports that use a range are expanded into single rules for each source/destination port.
This increases a lot the generated database.
