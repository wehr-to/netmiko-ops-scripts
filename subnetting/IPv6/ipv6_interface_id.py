# IPv6_interface_id.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load IPv6 Addresses
# - Load from CLI file or single input

#3: Extract Interface IDs
# - Parse IPv6 addresses and extract the interface identifier portion

#4: Annotate Results
# - Add original address and extracted interface ID

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from utils.logger import setup_logger

def extract_interface_id(address: str) -> str:
    try:
        ipv6 = ipaddress.IPv6Address(address)
        int_id = ipv6.packed[-8:]
        return ':'.join(f'{int_id[i]:02x}{int_id[i+1]:02x}' for i in range(0, 8, 2))
    except Exception:
        return "INVALID"

def load_ipv6_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def process_interface_ids(addresses: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for addr in addresses:
        interface_id = extract_interface_id(addr)
        logger.info(f"Processed: {addr} -> {interface_id}")
        results.append({
            "Original IPv6 Address": addr,
            "Interface ID": interface_id
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
    parser = argparse.ArgumentParser(description="Extract interface identifiers from IPv6 addresses")
    parser.add_argument('--input_file', help="File containing IPv6 addresses")
    parser.add_argument('--address', help="Single IPv6 address to process")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ipv6_interface_id", level=args.log_level)

    addresses = []
    if args.input_file:
        addresses.extend(load_ipv6_file(args.input_file))
    if args.address:
        addresses.append(args.address.strip())

    if not addresses:
        logger.error("No IPv6 addresses provided.")
        return

    results = process_interface_ids(addresses, logger)
    export_to_csv(results, args.output)
    logger.info(f"IPv6 interface ID extraction results saved to {args.output}")

if __name__ == '__main__':
    main()
