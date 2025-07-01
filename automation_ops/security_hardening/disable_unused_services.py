# disable_unused_services.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Detect unused or risky services (e.g., finger, tcp-small-servers)

#4: Annotate Results
# - Add IP, Hostname, and list of enabled legacy services

#5: Export
# - Write unused service report to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def parse_unused_services(output: str) -> List[Dict[str, str]]:
    risky_services = [
        "service finger",
        "service tcp-small-servers",
        "service udp-small-servers",
        "ip http server",
        "ip identd",
        "ip bootp server"
    ]
    services_found = []
    for line in output.splitlines():
        for svc in risky_services:
            if line.strip().startswith(svc):
                services_found.append({"Service": svc})
    if not services_found:
        services_found.append({"Service": "None Detected"})
    return services_found

def audit_unused_services(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_unused_services(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Unused service audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit unused services - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Service": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Detect unused or risky services in device configs")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("unused_services_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_unused_services(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Unused services audit saved to {args.output}")

if __name__ == '__main__':
    main()

