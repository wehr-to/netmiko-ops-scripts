# summarize_ospf_routes.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show ip route ospf'
# - Parse OSPF routes, metrics, and next hops

#4: Annotate Results
# - Add IP, Hostname, Route, Metric, Next Hop

#5: Export
# - Write OSPF route summary to CSV

import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_ospf_routes(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    for line in lines:
        if line.startswith('O '):
            match = re.match(r'O\s+(\S+)\s+\[\d+/(\d+)\]\s+via\s+(\S+)', line)
            if match:
                route = match.group(1)
                metric = match.group(2)
                next_hop = match.group(3)
                results.append({
                    "Route": route,
                    "Metric": metric,
                    "Next Hop": next_hop
                })
    return results

def summarize_ospf_routes(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip route ospf"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_ospf_routes(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: OSPF route summary collected")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to summarize OSPF routes - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Route": "ERROR", "Metric": "", "Next Hop": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Summarize OSPF routes from devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("summarize_ospf_routes", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(summarize_ospf_routes(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"OSPF route summary saved to {args.output}")

if __name__ == '__main__':
    main()
