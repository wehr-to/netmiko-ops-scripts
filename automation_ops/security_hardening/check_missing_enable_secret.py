# check_missing_enable_secret.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Check for 'enable secret' presence

#4: Annotate Results
# - Add IP, Hostname, and Compliance Status

#5: Export
# - Write check results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def check_enable_secret(output: str) -> List[Dict[str, str]]:
    has_enable_secret = any(re.match(r'^enable secret', line.strip()) for line in output.splitlines())
    return [{
        "Enable Secret Present": "Yes" if has_enable_secret else "No"
    }]

def audit_enable_secret(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = check_enable_secret(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Enable secret check complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to check enable secret - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Enable Secret Present": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Check for missing 'enable secret' on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("enable_secret_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_enable_secret(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Enable secret audit saved to {args.output}")

if __name__ == '__main__':
    main()

