# audit_password_encryption.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Search for password lines and check if encrypted

#4: Annotate Results
# - Add IP, Hostname, and Encryption Status

#5: Export
# - Write audit results to CSV

import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_password_encryption(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    for line in lines:
        if "password" in line and not line.strip().startswith("! "):
            encrypted = "7 " in line or "5 " in line
            results.append({
                "Line": line.strip(),
                "Encrypted": "Yes" if encrypted else "No"
            })
    return results

def audit_device_passwords(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_password_encryption(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Audited {len(parsed)} password lines")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit passwords - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Line": "ERROR", "Encrypted": str(e)}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Audit password encryption settings on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("password_audit", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_device_passwords(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Password encryption audit saved to {args.output}")

if __name__ == '__main__':
    main()

