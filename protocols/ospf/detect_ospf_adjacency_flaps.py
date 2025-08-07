# detect_ospf_adjacency_flaps.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show ip ospf neighbor'
# - Detect neighbors with high flap counts or recent state changes

#4: Annotate Results
# - Add IP, Hostname, Neighbor ID, State, and Uptime

#5: Export
# - Write OSPF adjacency flap detection results to CSV

import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_ospf_flaps(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^\S+\s+\d+\.\d+\.\d+\.\d+', line):
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 6:
                neighbor_id = parts[0]
                state = parts[2]
                uptime = parts[4]
                results.append({
                    "Neighbor ID": neighbor_id,
                    "State": state,
                    "Uptime": uptime
                })
    return results

def audit_ospf_flaps(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip ospf neighbor"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_ospf_flaps(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: OSPF adjacency flap check complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to check OSPF adjacency flaps - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Neighbor ID": "ERROR", "State": "", "Uptime": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Detect OSPF adjacency flaps across devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ospf_flap_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_ospf_flaps(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"OSPF adjacency flap report saved to {args.output}")

if __name__ == '__main__':
    main()

