# pull_interface_status.py connects to devices, runs show interface status, parses interface names and statuses, and writes them to a CSV.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_interface_status(output: str) -> List[Dict[str, str]]:
    interfaces = []
    lines = output.splitlines()
    header_found = False
    for line in lines:
        if re.match(r'^Port\s+Name\s+Status', line):
            header_found = True
            continue
        if header_found and line.strip():
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 3:
                interfaces.append({
                    "Interface": parts[0],
                    "Name": parts[1],
                    "Status": parts[2]
                })
    return interfaces


def get_interface_status(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show interface status"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_interface_status(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Retrieved {len(parsed)} interfaces")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to fetch interface status - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Interface": "ERROR", "Name": "", "Status": str(e)}]


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Pull interface status from all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("interface_status", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(get_interface_status(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Interface status data saved to {args.output}")


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show interface status'
# - Parse header and columns: Port, Name, Status

#4: Annotate Results
# - Add IP and Hostname to each interface entry

#5: Export
# - Write all interfaces to CSV

