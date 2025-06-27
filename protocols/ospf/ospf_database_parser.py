# ospf_database_parser.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show ip ospf database'
# - Parse LSA types, IDs, and age for topology analysis

#4: Annotate Results
# - Add IP, Hostname, LSA Type, LSA ID, Advertising Router, and Age

#5: Export
# - Write OSPF database summary to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_ospf_database(output: str) -> List[Dict[str, str]]:
    results = []
    lsa_blocks = re.split(r'\n(?=\s*\d+\.\d+\.\d+\.\d+)', output)
    current_type = ""
    for block in lsa_blocks:
        header_match = re.search(r'(Router Link States|Net Link States|Summary Net Link States|Summary ASB Link States|AS External Link States)', block)
        if header_match:
            current_type = header_match.group(1)
        lines = block.strip().splitlines()
        for line in lines:
            if re.match(r'^\s*\d+\.\d+\.\d+\.\d+', line):
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4:
                    lsa_id = parts[0]
                    adv_router = parts[1]
                    age = parts[2]
                    results.append({
                        "LSA Type": current_type,
                        "LSA ID": lsa_id,
                        "Advertising Router": adv_router,
                        "Age": age
                    })
    return results

def audit_ospf_database(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip ospf database"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_ospf_database(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: OSPF database parsed successfully")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to parse OSPF database - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "LSA Type": "ERROR", "LSA ID": "", "Advertising Router": "", "Age": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Parse and summarize OSPF database from devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ospf_database_parser", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_ospf_database(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"OSPF database summary saved to {args.output}")

if __name__ == '__main__':
    main()

