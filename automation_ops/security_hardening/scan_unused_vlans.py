# scan_unused_vlans.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show vlan brief'
# - Identify VLANs not assigned to any port

#4: Annotate Results
# - Add IP, Hostname, and unused VLAN info

#5: Export
# - Write unused VLAN report to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_unused_vlans(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^\d+\s+\S+', line):
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 3:
                vlan_id = parts[0]
                vlan_name = parts[1]
                interfaces = parts[2] if len(parts) > 2 else ""
                if interfaces.lower() == "" or interfaces.lower() == "none":
                    results.append({
                        "VLAN ID": vlan_id,
                        "VLAN Name": vlan_name,
                        "Used Interfaces": "None"
                    })
    return results

def scan_device_vlans(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show vlan brief"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_unused_vlans(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Found {len(parsed)} unused VLANs")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to scan VLANs - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "VLAN ID": "ERROR", "VLAN Name": "", "Used Interfaces": str(e)}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Scan for unused VLANs on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("unused_vlans", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(scan_device_vlans(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Unused VLAN report saved to {args.output}")

if __name__ == '__main__':
    main()
