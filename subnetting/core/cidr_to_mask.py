# cidr_to_mask.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load CIDR Prefixes
# - Load from CLI file or single input

#3: Convert to Netmask
# - Calculate subnet mask from CIDR prefix

#4: Annotate Results
# - Add CIDR and corresponding netmask

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from logger import setup_logger

def cidr_to_netmask(cidr: str) -> str:
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return str(network.netmask)
    except Exception:
        return "INVALID"

def load_cidr_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def process_cidrs(cidrs: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for cidr in cidrs:
        netmask = cidr_to_netmask(cidr)
        logger.info(f"Processed: {cidr} -> {netmask}")
        results.append({
            "CIDR": cidr,
            "Netmask": netmask
        })
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
    parser = argparse.ArgumentParser(description="Convert CIDR prefixes to subnet masks")
    parser.add_argument('--input_file', help="File containing CIDR prefixes")
    parser.add_argument('--cidr', help="Single CIDR prefix to convert")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("cidr_to_mask", level=args.log_level)

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
    logger.info(f"CIDR to netmask conversion results saved to {args.output}")

if __name__ == '__main__':
    main()

