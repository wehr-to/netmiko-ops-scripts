# disable_telnet.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config'
# - Detect if 'transport input telnet' is present under VTY

#4: Annotate Results
# - Add IP, Hostname, and Telnet status

#5: Export
# - Write telnet usage results to CSV

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_telnet_usage(output: str) -> List[Dict[str, str]]:
    results = []
    lines = output.splitlines()
    current_vty = None
    telnet_enabled = False
    for line in lines:
        if line.strip().startswith("line vty"):
            if current_vty is not None:
                results.append({"VTY Line": current_vty, "Telnet Enabled": "Yes" if telnet_enabled else "No"})
            current_vty = line.strip()
            telnet_enabled = False
        elif "transport input" in line and current_vty:
            if "telnet" in line:
                telnet_enabled = True
    if current_vty is not None:
        results.append({"VTY Line": current_vty, "Telnet Enabled": "Yes" if telnet_enabled else "No"})
    return results

def audit_telnet_status(device: Dict[str, str], logger) -> List[Dict[str, str]]:
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
        parsed = parse_telnet_usage(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Telnet usage audit complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to audit telnet usage - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "VTY Line": "ERROR", "Telnet Enabled": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Detect devices with Telnet enabled on VTY lines")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("telnet_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_telnet_status(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Telnet audit results saved to {args.output}")

if __name__ == '__main__':
    main()

