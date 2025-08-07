# verify_login_attempt_thresholds.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Look for 'login block-for', 'login quiet-mode', or max attempts settings

#4: Annotate Results
# - Add IP, Hostname, and login threshold status

#5: Export
# - Write login audit results to CSV

import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_login_thresholds(output: str) -> List[Dict[str, str]]:
    block_found = bool(re.search(r'login block-for', output))
    quiet_found = bool(re.search(r'login quiet-mode', output))
    return [{
        "Login Block-for Present": "Yes" if block_found else "No",
        "Login Quiet-mode Present": "Yes" if quiet_found else "No"
    }]

def audit_login_thresholds(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_login_thresholds(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Login attempt threshold audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit login thresholds - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Login Block-for Present": "ERROR", "Login Quiet-mode Present": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Verify login attempt threshold settings on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("login_thresholds", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_login_thresholds(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Login threshold audit saved to {args.output}")

if __name__ == '__main__':
    main()
