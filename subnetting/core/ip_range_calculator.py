# IP_range_calculator.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load CIDR Prefixes
# - Load from CLI file or single input

#3: Calculate Range
# - Determine first usable, last usable, broadcast address, and total hosts

#4: Annotate Results
# - Add CIDR, network, broadcast, first usable, last usable, total hosts

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from utils.logger import setup_logger

def calculate_ip_range(cidr: str) -> Dict[str, str]:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(net.hosts())
        first = str(hosts[0]) if hosts else str(net.network_address)
        last = str(hosts[-1]) if hosts else str(net.broadcast_address)
        return {
            "CIDR": cidr,
            "Network": str(net.network_address),
            "Broadcast": str(net.broadcast_address),
            "First Usable": first,
            "Last Usable": last,
            "Total Hosts": str(net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses)
        }
    except Exception:
        return {
            "CIDR": cidr,
            "Network": "INVALID",
            "Broadcast": "INVALID",
            "First Usable": "INVALID",
            "Last Usable": "INVALID",
            "Total Hosts": "INVALID"
        }

def load_cidr_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def process_cidrs(cidrs: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for cidr in cidrs:
        result = calculate_ip_range(cidr)
        logger.info(f"Processed: {cidr} -> {result}")
        results.append(result)
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
    parser = argparse.ArgumentParser(description="Calculate IPv4 address ranges from CIDR prefixes")
    parser.add_argument('--input_file', help="File containing CIDR prefixes")
    parser.add_argument('--cidr', help="Single CIDR prefix to calculate")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ip_range_calculator", level=args.log_level)

    cidrs = []
    if args.input_file:
        cidrs.extend(load_cidr_file(args.input_file))
    if args.cidr:
        cidrs.append(args.cidr.strip())

    if not cidrs:
        logger.error("No CIDR prefixes provided.")
        return

    results = process_cidrs(cidrs, logger)
    export_to_csv(results, args.output)
    logger.info(f"IP range calculation results saved to {args.output}")

if __name__ == '__main__':
    main()

