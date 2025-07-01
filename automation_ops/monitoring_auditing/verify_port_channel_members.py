# verify_port_channel_members.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show etherchannel summary'
# - Extract Port-channel ID, Protocol, and Member Interfaces

#4: Annotate Results
# - Add IP and Hostname to each port-channel entry

#5: Export
# - Write port-channel data to CSV

import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_port_channels(output: str) -> List[Dict[str, str]]:
    port_channels = []
    lines = output.splitlines()
    for line in lines:
        if re.match(r'^\d+\s+Po\d+\s+.*', line):
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 4:
                port_channels.append({
                    "Group": parts[0],
                    "Port-Channel": parts[1],
                    "Protocol": parts[2],
                    "Members": parts[3]
                })
    return port_channels

def get_port_channel_members(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show etherchannel summary"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_port_channels(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Retrieved {len(parsed)} port-channel entries")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to fetch port-channel data - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Port-Channel": "ERROR", "Group": "", "Protocol": "", "Members": str(e)}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Verify port-channel members on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("port_channels", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(get_port_channel_members(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Port-channel data saved to {args.output}")

if __name__ == '__main__':
    main()
