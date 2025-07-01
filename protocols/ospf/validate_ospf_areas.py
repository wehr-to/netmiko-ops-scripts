# validate_ospf_areas.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show ip ospf interface brief'
# - Parse interfaces with their associated OSPF areas

#4: Annotate Results
# - Add IP, Hostname, Interface, and Area ID

#5: Export
# - Write OSPF area validation results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_ospf_areas(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^\S+', line):
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 4:
                interface = parts[0]
                area = parts[3]
                results.append({
                    "Interface": interface,
                    "Area": area
                })
    return results

def validate_ospf_areas(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip ospf interface brief"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_ospf_areas(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: OSPF area validation complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to validate OSPF areas - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Interface": "ERROR", "Area": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Validate OSPF area assignments on devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("validate_ospf_areas", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(validate_ospf_areas(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"OSPF area validation results saved to {args.output}")

if __name__ == '__main__':
    main()
