# IPv6_range_calculator.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load IPv6 Subnets
# - Load from CLI file or single input

#3: Calculate Range
# - Determine first usable, last usable, and broadcast (not applicable for IPv6, note N/A)

#4: Annotate Results
# - Add subnet, prefix length, first address, last address, and number of hosts

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from logger import setup_logger

def calculate_ipv6_range(subnet: str) -> Dict[str, str]:
    try:
        net = ipaddress.IPv6Network(subnet, strict=False)
        first = str(net.network_address)
        last = str(net.broadcast_address)
        hosts = net.num_addresses
        return {
            "Subnet": subnet,
            "Prefix Length": str(net.prefixlen),
            "First Address": first,
            "Last Address": last,
            "Total Addresses": str(hosts),
            "Broadcast": "N/A"
        }
    except Exception:
        return {
            "Subnet": subnet,
            "Prefix Length": "INVALID",
            "First Address": "INVALID",
            "Last Address": "INVALID",
            "Total Addresses": "INVALID",
            "Broadcast": "INVALID"
        }

def load_subnet_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def process_subnets(subnets: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for subnet in subnets:
        result = calculate_ipv6_range(subnet)
        logger.info(f"Processed: {subnet} -> {result}")
        results.append(result)
    return results

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Calculate IPv6 subnet address ranges")
    parser.add_argument('--input_file', help="File containing IPv6 subnets")
    parser.add_argument('--subnet', help="Single IPv6 subnet to process")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ipv6_range_calculator", level=args.log_level)

    subnets = []
    if args.input_file:
        subnets.extend(load_subnet_file(args.input_file))
    if args.subnet:
        subnets.append(args.subnet.strip())

    if not subnets:
        logger.error("No IPv6 subnets provided.")
        return

    results = process_subnets(subnets, logger)
    export_to_csv(results, args.output)
    logger.info(f"IPv6 range calculation results saved to {args.output}")

if __name__ == '__main__':
    main()

