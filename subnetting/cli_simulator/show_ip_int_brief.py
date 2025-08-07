# show_ip_int_brief.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show ip interface brief'
# - Parse interface, IP address, status, protocol

#4: Annotate Results
# - Add IP, Hostname, Interface, IP Address, Status, Protocol

#5: Export
# - Write results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_show_ip_int_brief(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^(\S+)\s+(\S+)\s+YES', line):
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 6:
                results.append({
                    "Interface": parts[0],
                    "IP Address": parts[1],
                    "Status": parts[4],
                    "Protocol": parts[5]
                })
    return results

def pull_show_ip_int_brief(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip interface brief"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_show_ip_int_brief(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Pulled show ip interface brief")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to pull show ip interface brief - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Interface": "ERROR", "IP Address": "", "Status": "", "Protocol": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Pull 'show ip interface brief' from devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("show_ip_int_brief", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(pull_show_ip_int_brief(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"'show ip interface brief' results saved to {args.output}")

if __name__ == '__main__':
    main()

