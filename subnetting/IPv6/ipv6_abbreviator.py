# ipv6_abbreviator.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load IPv6 Addresses
# - Load from CLI file or single input

#3: Abbreviate
# - Use ipaddress to compress IPv6 addresses

#4: Annotate Results
# - Add original and abbreviated address columns

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from utils.logger import setup_logger

def abbreviate_ipv6_address(address: str) -> str:
    try:
        return str(ipaddress.IPv6Address(address).compressed)
    except Exception:
        return "INVALID"

def load_ipv6_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def process_ipv6_addresses(addresses: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for addr in addresses:
        abbreviated = abbreviate_ipv6_address(addr)
        logger.info(f"Processed: {addr} -> {abbreviated}")
        results.append({
            "Original IPv6 Address": addr,
            "Abbreviated IPv6 Address": abbreviated
        })
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
    parser = argparse.ArgumentParser(description="Abbreviate IPv6 addresses")
    parser.add_argument('--input_file', help="File containing IPv6 addresses")
    parser.add_argument('--address', help="Single IPv6 address to abbreviate")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ipv6_abbreviator", level=args.log_level)

    addresses = []
    if args.input_file:
        addresses.extend(load_ipv6_file(args.input_file))
    if args.address:
        addresses.append(args.address.strip())

    if not addresses:
        logger.error("No IPv6 addresses provided.")
        return

    results = process_ipv6_addresses(addresses, logger)
    export_to_csv(results, args.output)
    logger.info(f"IPv6 abbreviation results saved to {args.output}")

if __name__ == '__main__':
    main()

