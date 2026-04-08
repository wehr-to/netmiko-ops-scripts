# site_ip_planner.py

#1: Imports & Setup
# - argparse, csv, ipaddress, yaml, logger

#2: Load Site Plan Requirements
# - Load from YAML (site name, required subnets, host counts)

#3: Generate Subnet Plan
# - Allocate subnets from a given supernet based on host counts

#4: Annotate Results
# - Add site name, allocated subnet, and host capacity

#5: Export
# - Write results to CSV

import argparse
import csv
import ipaddress
import yaml
from typing import List, Dict
from utils.logger import setup_logger

def load_site_plan(file_path: str) -> List[Dict[str, str]]:
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def generate_subnet_plan(supernet: str, site_plans: List[Dict[str, str]], logger) -> List[Dict[str, str]]:
    results = []
    try:
        pool = list(ipaddress.IPv4Network(supernet).subnets(new_prefix=24))
    except Exception as e:
        logger.log_error(f"Invalid supernet: {supernet} | {e}")
        return []

    used = 0
    for site in site_plans:
        site_name = site.get('site_name', 'Unknown')
        required_hosts = int(site.get('required_hosts', 0))
        prefix_length = 32 - (required_hosts - 1).bit_length()
        while prefix_length < 24:
            prefix_length += 1

        found = False
        while used < len(pool):
            candidate = list(pool[used].subnets(new_prefix=prefix_length))[0]
            used += 1
            results.append({
                "Site Name": site_name,
                "Allocated Subnet": str(candidate),
                "Required Hosts": str(required_hosts),
                "Allocated Prefix Length": str(candidate.prefixlen),
                "Usable Hosts": str(candidate.num_addresses - 2 if candidate.num_addresses > 2 else candidate.num_addresses)
            })
            logger.log_info(f"Allocated {candidate} to {site_name} for {required_hosts} hosts")
            found = True
            break
        if not found:
            logger.log_error(f"Unable to allocate subnet for {site_name} with {required_hosts} hosts")

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
    parser = argparse.ArgumentParser(description="Generate site subnet plans from a supernet and YAML site requirements")
    parser.add_argument('--supernet', required=True, help="Supernet to allocate from, e.g., 10.0.0.0/16")
    parser.add_argument('--site_plan', required=True, help="YAML file with site_name and required_hosts")
    parser.add_argument('--output', required=True, help="CSV output file for the allocation plan")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("site_ip_planner", level=args.log_level)

    site_plans = load_site_plan(args.site_plan)
    results = generate_subnet_plan(args.supernet, site_plans, logger)

    export_to_csv(results, args.output)
    logger.log_info(f"Site IP plan saved to {args.output}")

if __name__ == '__main__':
    main()

