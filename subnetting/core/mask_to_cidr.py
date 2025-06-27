# mask_to_cidr.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load Masks and IPs
# - Load from CLI file or single input

#3: Convert to CIDR
# - Convert IP and subnet mask to CIDR prefix

#4: Annotate Results
# - Add IP, mask, and resulting CIDR

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from logger import setup_logger

def mask_to_cidr(ip: str, mask: str) -> str:
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network.with_prefixlen)
    except Exception:
        return "INVALID"

def load_ip_mask_file(file_path: str) -> List[Dict[str, str]]:
    results = []
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'ip' in row and 'mask' in row:
                results.append({'ip': row['ip'].strip(), 'mask': row['mask'].strip()})
    return results

def process_ip_masks(ip_masks: List[Dict[str, str]], logger) -> List[Dict[str, str]]:
    results = []
    for entry in ip_masks:
        cidr = mask_to_cidr(entry['ip'], entry['mask'])
        logger.info(f"Processed: {entry['ip']} {entry['mask']} -> {cidr}")
        results.append({
            "IP Address": entry['ip'],
            "Subnet Mask": entry['mask'],
            "CIDR": cidr
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
    parser = argparse.ArgumentParser(description="Convert IP and subnet mask to CIDR prefix")
    parser.add_argument('--input_file', help="CSV file with 'ip' and 'mask' columns")
    parser.add_argument('--ip', help="Single IP address")
    parser.add_argument('--mask', help="Single subnet mask")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("mask_to_cidr", level=args.log_level)

    ip_masks = []
    if args.input_file:
        ip_masks.extend(load_ip_mask_file(args.input_file))
    if args.ip and args.mask:
        ip_masks.append({'ip': args.ip.strip(), 'mask': args.mask.strip()})

    if not ip_masks:
        logger.error("No IP and mask pairs provided.")
        return

    results = process_ip_masks(ip_masks, logger)
    export_to_csv(results, args.output)
    logger.info(f"Mask to CIDR conversion results saved to {args.output}")

if __name__ == '__main__':
    main()
