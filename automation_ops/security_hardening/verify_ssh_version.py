# verify_ssh_version.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Verify SSH version setting (preferably version 2 only)

#4: Annotate Results
# - Add IP, Hostname, and SSH version configuration

#5: Export
# - Write SSH version audit results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_ssh_version(output: str) -> List[Dict[str, str]]:
    ssh_v1_enabled = bool(re.search(r'ip ssh version 1', output))
    ssh_v2_enabled = bool(re.search(r'ip ssh version 2', output))
    return [{
        "SSH Version 1 Enabled": "Yes" if ssh_v1_enabled else "No",
        "SSH Version 2 Enabled": "Yes" if ssh_v2_enabled else "No"
    }]

def audit_ssh_version(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_ssh_version(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: SSH version audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit SSH version - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "SSH Version 1 Enabled": "ERROR", "SSH Version 2 Enabled": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Verify SSH version configuration on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ssh_version_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_ssh_version(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"SSH version audit saved to {args.output}")

if __name__ == '__main__':
    main()
