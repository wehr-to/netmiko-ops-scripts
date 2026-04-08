# vlsm_allocator.py

#1: Imports & Setup
# - argparse, csv, ipaddress, yaml, logger

#2: Load Subnet Requirements
# - Load from YAML (name, required_hosts) for VLSM allocation

#3: Allocate VLSM Subnets
# - Sort by required hosts descending, allocate smallest fitting subnets from base network

#4: Annotate Results
# - Add name, allocated subnet, usable hosts

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
import yaml
from typing import List, Dict
from utils.logger import setup_logger

def load_requirements(file_path: str) -> List[Dict[str, str]]:
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def allocate_vlsm(base_network: str, requirements: List[Dict[str, str]], logger) -> List[Dict[str, str]]:
    results = []
    try:
        network_pool = ipaddress.IPv4Network(base_network, strict=False)
        free_subnets = [network_pool]
    except Exception as e:
        logger.log_error(f"Invalid base network: {base_network} | {e}")
        return []

    sorted_reqs = sorted(requirements, key=lambda x: int(x.get('required_hosts', 0)), reverse=True)

    for req in sorted_reqs:
        name = req.get('name', 'Unknown')
        required_hosts = int(req.get('required_hosts', 0))
        prefix_length = 32 - (required_hosts + 2 - 1).bit_length()

        allocated = None
        for idx, subnet in enumerate(free_subnets):
            if subnet.prefixlen <= prefix_length:
                subnets = list(subnet.subnets(new_prefix=prefix_length))
                allocated = subnets[0]
                free_subnets.pop(idx)
                free_subnets.extend(subnets[1:])
                break

        if allocated:
            results.append({
                "Name": name,
                "Allocated Subnet": str(allocated),
                "Required Hosts": str(required_hosts),
                "Prefix Length": str(allocated.prefixlen),
                "Usable Hosts": str(allocated.num_addresses - 2 if allocated.num_addresses > 2 else allocated.num_addresses)
            })
            logger.log_info(f"Allocated {allocated} to {name} for {required_hosts} hosts")
        else:
            results.append({
                "Name": name,
                "Allocated Subnet": "Allocation Failed",
                "Required Hosts": str(required_hosts),
                "Prefix Length": "-",
                "Usable Hosts": "-"
            })
            logger.log_error(f"Failed to allocate subnet for {name} requiring {required_hosts} hosts")

    return results

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = data[0].keys()
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="VLSM allocator for site subnet planning")
    parser.add_argument('--base_network', required=True, help="Base network to allocate from, e.g., 192.168.0.0/24")
    parser.add_argument('--requirements', required=True, help="YAML file with name and required_hosts per subnet")
    parser.add_argument('--output', required=True, help="CSV output file for allocation plan")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("vlsm_allocator", level=args.log_level)

    requirements = load_requirements(args.requirements)
    results = allocate_vlsm(args.base_network.strip(), requirements, logger)

    export_to_csv(results, args.output)
    logger.log_info(f"VLSM allocation results saved to {args.output}")

if __name__ == '__main__':
    main()
