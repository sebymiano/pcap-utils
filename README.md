# classbench-to-iptables
Convert classbench rules to bpf/-iptables counterparts

This repository contains a simple Python script that can be used to convert automatically generated Classbench rules into a set of rules that can be loaded in either `iptables` or `bpf-iptables`.

## Usage

To use the script you can simply update the global variables at the start of the file.
Within the current behaviour, source and destination ports that use a range are expanded into single rules for each source/destination port.
This increases a lot the generated database.

The list of parameters can be found below
```
python classbench-2-iptables.py --help
usage: classbench-2-iptables.py [-h] [-n {iptables,pcn-iptables}] [-c {INPUT,FORWARD,OUTPUT}] -i INPUT_FILE -o OUTPUT_FILE

Program used to convert Classbench rules into pcn/iptables rules

optional arguments:
  -h, --help            show this help message and exit
  -n {iptables,pcn-iptables}, --name {iptables,pcn-iptables}
                        The name of the program to use
  -c {INPUT,FORWARD,OUTPUT}, --chain {INPUT,FORWARD,OUTPUT}
                        The chain where to append the rules
  -i INPUT_FILE, --input-file INPUT_FILE
                        The Classbench input file
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        The output file where to same the ruleset
```