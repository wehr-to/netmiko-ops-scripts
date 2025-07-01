# check_weak_enable_passwords.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Detect 'enable password' usage and flag as weak

#4: Annotate Results
# - Add IP, Hostname, and Weak Password status

#5: Export
# - Write weak password check results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_weak_enable_password(output: str) -> List[Dict[str, str]]:
    lines = output.splitlines()
    weak_used = any(re.match(r'^enable password\s+', line.strip()) for line in lines)
    return [{
        "Enable Password Used": "Yes" if weak_used else "No"
    }]

def audit_weak_enable_passwords(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_weak_enable_password(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Weak enable password audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to check weak enable passwords - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Enable Password Used": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Check for weak 'enable password' usage on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("weak_enable_passwords", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_weak_enable_passwords(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Weak enable password audit saved to {args.output}")

if __name__ == '__main__':
    main()

