import random
import time
from scapy.all import *
from tqdm import tqdm  # Progress bar
import argparse
import yaml
import ipaddress

CONFIG_file_default = f"{sys.path[0]}/udp_uniform_config.yaml"

# Function to send multiple UDP packets and their responses for a flow in a batch
def generate_udp_packets_batch(src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, packet_size, batch_size, generate_responses):
    packets = []
    
    for _ in range(batch_size):
        # Create UDP packet (source -> destination)
        payload = "X" * (packet_size - 42)  # 42 bytes for Ethernet + UDP/IP headers
        udp_packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
        packets.append(udp_packet)

        if generate_responses:
            # Create response packet (destination -> source)
            response_payload = "Y" * (packet_size - 42)  # Response payload
            response_packet = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / UDP(sport=dst_port, dport=src_port) / Raw(load=response_payload)
            packets.append(response_packet)
    
    return packets

# Function to randomly select an IP address from an IP range
def get_random_ip_from_range(ip_range):
    network = ipaddress.IPv4Network(ip_range)
    return str(random.choice(list(network.hosts())))

# Function to randomly select a port from a given range
def get_random_port(port_range):
    return random.randint(port_range[0], port_range[1])

# Function to emulate interleaving of multiple UDP flows in a single process with batching
def create_interleaved_udp_traffic(src_ip_range, dst_ip_range, src_mac, dst_mac, src_port_range, dst_port_range, num_flows, packets_per_flow, packet_size, batch_size, generate_responses):
    total_packets = []
    
    # Progress bar to track packet generation
    total_steps = num_flows * packets_per_flow * (2 if generate_responses else 1)  # Multiply by 2 to account for response packets if needed
    progress_bar = tqdm(total=total_steps, desc="Generating UDP traffic with interleaving", unit="packet")
    
    # Initialize state for each flow
    flows = []
    for flow_id in range(num_flows):
        src_ip = get_random_ip_from_range(dst_ip_range)  # Pick a random client IP
        dst_ip = get_random_ip_from_range(src_ip_range)  # Pick a random server IP
        # src_port = 1024 + flow_id
        # dst_port = random.randint(1025, 65535)
        src_port = get_random_port(src_port_range)  # Pick a random source port
        dst_port = get_random_port(dst_port_range)  # Pick a random destination port
        flows.append((src_ip, dst_ip, src_port, dst_port))
    
    # Calculate how many rounds we need to generate all packets
    rounds = (packets_per_flow + batch_size - 1) // batch_size  # Ceiling division to cover all packets
    
    for round_id in range(rounds):
        for flow in flows:
            src_ip, dst_ip, src_port, dst_port = flow
            
            # Generate a batch of UDP packets and responses for this flow
            packets = generate_udp_packets_batch(src_ip, dst_ip, dst_mac, src_mac, src_port, dst_port, packet_size, batch_size, generate_responses)
            total_packets.extend(packets)
            
            # Update progress bar for the number of packets generated in this batch
            progress_bar.update(min(batch_size * (2 if generate_responses else 1), packets_per_flow * (2 if generate_responses else 1) - round_id * batch_size * (2 if generate_responses else 1)))
    
    # Close the progress bar
    progress_bar.close()
    
    return total_packets

# Example usage
if __name__ == "__main__":
    desc = """Generate pcap file for UDP traffic with interleaving"""

    parser = argparse.ArgumentParser(description = desc)
    parser.add_argument("-c", "--config-file", type=str, default=CONFIG_file_default, help="The YAML config file")
    parser.add_argument("-o", '--out', required = True, help='Output pcap file name')

    args = parser.parse_args()

    if (os.path.isfile(args.out)):
        print('"{}" already exists, refusing to overwrite.'.format(args.out))
        sys.exit(-1)

    with open(args.config_file, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(-1)

    src_ip_range = config['src_ip_range']  # Range for server IPs
    dst_ip_range = config['dst_ip_range']  # Range for client IPs
    src_mac = config['src_mac']  # Server MAC address
    dst_mac = config['dst_mac']  # Client MAC address
    num_flows = config['num_flows']
    packets_per_flow = config['packets_per_flow']
    packet_size = config['packet_size'] 
    generate_responses = bool(config['generate_responses'])  # Generate response packets for each packet
    src_port_range = (config['src_port_start'], config['src_port_end'])  # Range for source ports
    dst_port_range = (config['dst_port_start'], config['dst_port_end'])  # Range for destination ports

    # Generate N packets per flow before switching to the next flow
    batch_size = config['batch_size']

    if batch_size > packets_per_flow:
        print("Batch size cannot be greater than packets per flow")
        sys.exit(-1)
    
    packets = create_interleaved_udp_traffic(src_ip_range, dst_ip_range, src_mac, dst_mac, src_port_range, dst_port_range, num_flows, packets_per_flow, packet_size, batch_size, generate_responses)
    
    # You can either send the packets out on the network or save them to a file:
    # Send the packets (Warning: requires root privileges)
    # send(packets)

    # Or write to a pcap file
    wrpcap(args.out, packets)
