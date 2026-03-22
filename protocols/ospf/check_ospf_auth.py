# check_ospf_auth.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Check OSPF interfaces for authentication configuration

#4: Annotate Results
# - Add IP, Hostname, Interface, and Auth Status

#5: Export
# - Write OSPF authentication audit results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_ospf_auth(output: str) -> List[Dict[str, str]]:
    results = []
    interfaces = re.findall(r'(interface \S+)([\s\S]*?)(?=^interface|^router|\Z)', output, re.MULTILINE)
    for intf_block, config in interfaces:
        ospf_enabled = "ip ospf" in config
        auth_present = "ip ospf authentication" in config or "ip ospf authentication message-digest" in config
        if ospf_enabled:
            results.append({
                "Interface": intf_block.split()[1],
                "OSPF Authentication": "Enabled" if auth_present else "Not Enabled"
            })
    return results

def audit_ospf_auth(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show running-config"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_ospf_auth(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: OSPF authentication audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit OSPF authentication - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Interface": "ERROR", "OSPF Authentication": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Check OSPF interface authentication on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ospf_auth_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_ospf_auth(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"OSPF authentication audit saved to {args.output}")

if __name__ == '__main__':
    main()

