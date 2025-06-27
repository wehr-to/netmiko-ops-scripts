# enforce_login_banners.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Detect if banner login and/or banner motd are configured

#4: Annotate Results
# - Add IP, Hostname, and banner presence status

#5: Export
# - Write banner audit results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_banner_presence(output: str) -> List[Dict[str, str]]:
    login_found = bool(re.search(r'^banner login', output, re.MULTILINE))
    motd_found = bool(re.search(r'^banner motd', output, re.MULTILINE))
    return [{
        "Banner MOTD Present": "Yes" if motd_found else "No",
        "Banner Login Present": "Yes" if login_found else "No"
    }]

def audit_login_banners(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_banner_presence(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Login banner audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit banners - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Banner MOTD Present": "ERROR", "Banner Login Present": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Audit presence of login and MOTD banners on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("login_banner_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_login_banners(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Banner presence audit saved to {args.output}")

if __name__ == '__main__':
    main()

