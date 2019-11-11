# classbench-to-iptables
Convert classbench rules to bpf/-iptables counterparts

This repository contains a simple Python script that can be used to convert automatically generated Classbench rules into a set of rules that can be loaded in either `iptables` or `bpf-iptables`.

## Usage

The list of parameters can be found below
```
python3 classbench-to-iptables.py --help
usage: classbench-to-iptables.py [-h] -i INPUT_FILE -o OUTPUT_FILE                                                                     
                                 [-n {iptables,pcn-iptables}]                                                                          
                                 [-c {INPUT,FORWARD,OUTPUT}] [-e EXPAND_RANGE]                                                         
                                 [-j {ACCEPT,DROP}]                                                                                    

Program used to convert Classbench rules into pcn/iptables rules

optional arguments:                                                                                                                    
  -h, --help            show this help message and exit                                                                                
  -i INPUT_FILE, --input-file INPUT_FILE                                                                                               
                        The Classbench input file                                                                                      
  -o OUTPUT_FILE, --output-file OUTPUT_FILE                                                                                            
                        The output file where to same the ruleset                                                                      
  -n {iptables,pcn-iptables}, --name {iptables,pcn-iptables}                                                                           
                        The name of the program to use                                                                                 
  -c {INPUT,FORWARD,OUTPUT}, --chain {INPUT,FORWARD,OUTPUT}                                                                            
                        The chain where to append the rules                                                                            
  -e EXPAND_RANGE, --expand-range EXPAND_RANGE                                                                                         
                        Create a separate rule for each port range value                                                               
  -j {ACCEPT,DROP}, --default-action {ACCEPT,DROP}                                                                                     
                        Default action to use in the rule
```


# classbench-to-pcap
Convert classbench generated ruleset to pcap file using the Python `scapy` library.

## Usage

```
usage: classbench-to-pcap.py [-h] -i INPUT_FILE -o OUTPUT_FILE 
                             [-s SRC_MAC] [-d DST_MAC] [-l PKT_SIZE]                                                                                │
                                                                                                                                       
Program used to generate pcap trace from Classbench generated traces                                                                   
                                                                                                                                       
optional arguments:                                                                                                                    
  -h, --help            show this help message and exit                                                                                
  -i INPUT_FILE, --input-file INPUT_FILE                                                                                               
                        The Classbench trace input file                                                                                
  -o OUTPUT_FILE, --output-file OUTPUT_FILE                                                                                            
                        The output pcap file                                                                                           
  -s SRC_MAC, --src-mac SRC_MAC                                                                                                        
                        Source MAC address to use in the generated pcap                                                                
  -d DST_MAC, --dst-mac DST_MAC                                                                                                        
                        Destination MAC address to use in the generated pcap                                                           
  -l PKT_SIZE, --pkt-size PKT_SIZE                                                                                                     
                        Size of the generated packet
```