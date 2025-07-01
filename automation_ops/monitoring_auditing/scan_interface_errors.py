# scan_interface_errors.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show interfaces'
# - Extract input/output errors per interface

#4: Annotate Results
# - Add IP and Hostname to each interface entry

#5: Export
# - Write error summary to CSV

import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_interface_errors(output: str) -> List[Dict[str, str]]:
    interfaces = []
    matches = re.findall(r'(\S+) is (?:administratively )?up, line protocol is (up|down).*?\n.*?\n.*?\n.*?\n.*?\n.*?\n.*?\n.*?\n\s+\d+ input errors, \d+ CRC, \d+ frame, \d+ overrun, \d+ ignored\n\s+(\d+) output errors', output, re.DOTALL)
    for intf, status, out_errors in matches:
        interfaces.append({
            "Interface": intf,
            "Status": status,
            "Output Errors": out_errors
        })
    return interfaces

def get_interface_errors(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show interfaces"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_interface_errors(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Retrieved {len(parsed)} interface error entries")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to fetch interface errors - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Interface": "ERROR", "Status": "", "Output Errors": str(e)}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Scan interface errors from all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("interface_errors", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(get_interface_errors(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Interface error data saved to {args.output}")

if __name__ == '__main__':
    main()

