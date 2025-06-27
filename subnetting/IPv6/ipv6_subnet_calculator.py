# ipv6_subnet_calculator.py

#1: Imports & Setup
# - argparse, csv, ipaddress, logger

#2: Load Base Subnet and New Prefix
# - Load from CLI arguments

#3: Calculate Subnets
# - Calculate all subnets within base subnet using new prefix

#4: Annotate Results
# - Add base subnet, new prefix, and list of generated subnets

#5: Export
# - Write subnet calculation results to CSV

import argparse
import csv
import ipaddress
from typing import List, Dict
from logger import setup_logger

def calculate_ipv6_subnets(base_subnet: str, new_prefix: int) -> List[Dict[str, str]]:
    results = []
    try:
        net = ipaddress.IPv6Network(base_subnet, strict=False)
        subnets = list(net.subnets(new_prefix=new_prefix))
        for subnet in subnets:
            results.append({
                "Base Subnet": base_subnet,
                "New Prefix": str(new_prefix),
                "Generated Subnet": str(subnet)
            })
        return results
    except Exception:
        return [{
            "Base Subnet": base_subnet,
            "New Prefix": str(new_prefix),
            "Generated Subnet": "INVALID"
        }]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Calculate IPv6 subnets within a base subnet")
    parser.add_argument('--base_subnet', required=True, help="Base IPv6 subnet, e.g., 2001:db8::/48")
    parser.add_argument('--new_prefix', required=True, type=int, help="New prefix length, e.g., 64")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ipv6_subnet_calculator", level=args.log_level)

    results = calculate_ipv6_subnets(args.base_subnet.strip(), args.new_prefix)
    export_to_csv(results, args.output)
    logger.info(f"IPv6 subnet calculation results saved to {args.output}")

if __name__ == '__main__':
    main()

