# check_missing_vty_acl.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Search VTY lines for missing 'access-class'

#4: Annotate Results
# - Add IP, Hostname, and ACL status for each VTY block

#5: Export
# - Write ACL check results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_vty_acl(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    current_vty = None
    has_acl = False
    for line in lines:
        if line.strip().startswith("line vty"):
            if current_vty is not None:
                results.append({"VTY Line": current_vty, "Access-Class Present": "Yes" if has_acl else "No"})
            current_vty = line.strip()
            has_acl = False
        elif "access-class" in line and current_vty:
            has_acl = True
    if current_vty is not None:
        results.append({"VTY Line": current_vty, "Access-Class Present": "Yes" if has_acl else "No"})
    return results

def audit_vty_acls(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_vty_acl(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Audited {len(parsed)} VTY lines")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to check VTY ACLs - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "VTY Line": "ERROR", "Access-Class Present": str(e)}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Check for missing VTY ACLs on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("vty_acl_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_vty_acls(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"VTY ACL check results saved to {args.output}")

if __name__ == '__main__':
    main()

