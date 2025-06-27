# scan_ospf_timer_mismatches.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show ip ospf interface'
# - Parse hello/dead intervals per interface

#4: Annotate Results
# - Add IP, Hostname, Interface, Hello Interval, Dead Interval

#5: Export
# - Write OSPF timer scan results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_ospf_timers(output: str) -> List[Dict[str, str]]:
    results = []
    interfaces = re.split(r'\n(?=\S)', output)
    for block in interfaces:
        intf_match = re.search(r'^(.+) is up', block)
        hello_match = re.search(r'Hello (\d+)', block)
        dead_match = re.search(r'Dead (\d+)', block)
        if intf_match and hello_match and dead_match:
            results.append({
                "Interface": intf_match.group(1).strip(),
                "Hello Interval": hello_match.group(1),
                "Dead Interval": dead_match.group(1)
            })
    return results

def scan_ospf_timers(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip ospf interface"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_ospf_timers(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: OSPF timer scan complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to scan OSPF timers - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Interface": "ERROR", "Hello Interval": "", "Dead Interval": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Scan OSPF interfaces for hello/dead timer mismatches")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ospf_timer_scan", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(scan_ospf_timers(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"OSPF timer scan results saved to {args.output}")

if __name__ == '__main__':
    main()

