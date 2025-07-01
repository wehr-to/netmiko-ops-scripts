# wildcard_mask.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load Subnet Masks
# - Load from CLI file or single input

#3: Calculate Wildcard Mask
# - Calculate wildcard mask from subnet mask

#4: Annotate Results
# - Add subnet mask and calculated wildcard mask

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from utils.logger import setup_logger

def calculate_wildcard_mask(mask: str) -> str:
    try:
        net = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        wildcard = ipaddress.IPv4Address(int(ipaddress.IPv4Address('255.255.255.255')) ^ int(net.netmask))
        return str(wildcard)
    except Exception:
        return "INVALID"

def load_mask_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def process_masks(masks: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for mask in masks:
        wildcard = calculate_wildcard_mask(mask)
        logger.info(f"Processed: {mask} -> {wildcard}")
        results.append({
            "Subnet Mask": mask,
            "Wildcard Mask": wildcard
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
    parser = argparse.ArgumentParser(description="Calculate wildcard masks from subnet masks")
    parser.add_argument('--input_file', help="File containing subnet masks")
    parser.add_argument('--mask', help="Single subnet mask to calculate")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("wildcard_mask", level=args.log_level)

    masks = []
    if args.input_file:
        masks.extend(load_mask_file(args.input_file))
    if args.mask:
        masks.append(args.mask.strip())

    if not masks:
        logger.error("No subnet masks provided.")
        return

    results = process_masks(masks, logger)
    export_to_csv(results, args.output)
    logger.info(f"Wildcard mask calculation results saved to {args.output}")

if __name__ == '__main__':
    main()

