# IP_helpers.py (Enhanced with validation and binary/decimal conversion)

#1: Imports & Setup
# - argparse, csv, yaml, ipaddress, re, logger

#2: Load Helper Configurations
# - Load from YAML or CSV

#3: Validate & Convert IPs
# - Validate helper addresses, convert dotted binary to decimal if needed
# - Validate interface name syntax

#4: Generate Config
# - Create 'ip helper-address' CLI commands per interface

#5: Annotate Results
# - Add interface, helper address (validated/converted), and generated config

#6: Export
# - Write results to CSV

import argparse
import csv
import yaml
import ipaddress
import re
from typing import List, Dict
from logger import setup_logger

def load_helpers_file(file_path: str) -> List[Dict[str, str]]:
    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        helpers = []
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                helpers.append(row)
        return helpers

def convert_binary_ip_to_decimal(ip_str: str) -> str:
    try:
        if re.match(r'^[01]{8}(\.[01]{8}){3}$', ip_str):
            parts = ip_str.split('.')
            return '.'.join(str(int(part, 2)) for part in parts)
        return ip_str
    except Exception:
        return "INVALID"

def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except Exception:
        return False

def validate_interface_name(name: str) -> bool:
    return bool(re.match(r'^(GigabitEthernet|FastEthernet|Ethernet|TenGigabitEthernet)[0-9/]+$', name))

def generate_ip_helper_config(entry: Dict[str, str], logger) -> Dict[str, str]:
    interface = entry.get('interface', '').strip()
    helper_raw = entry.get('helper_address', '').strip()
    helper_converted = convert_binary_ip_to_decimal(helper_raw)

    if not validate_interface_name(interface):
        logger.error(f"Invalid interface name: {interface}")
        return {
            "Interface": interface,
            "Helper Address": helper_raw,
            "Generated Config": "INVALID INTERFACE"
        }

    if not validate_ip(helper_converted):
        logger.error(f"Invalid helper address: {helper_raw}")
        return {
            "Interface": interface,
            "Helper Address": helper_raw,
            "Generated Config": "INVALID IP"
        }

    config = f"interface {interface}\n ip helper-address {helper_converted}"
    logger.info(f"Generated helper config for {interface} with helper {helper_converted}")

    return {
        "Interface": interface,
        "Helper Address": helper_converted,
        "Generated Config": config
    }

def process_helpers(helpers: List[Dict[str, str]], logger) -> List[Dict[str, str]]:
    results = []
    for entry in helpers:
        result = generate_ip_helper_config(entry, logger)
        results.append(result)
    return results

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = data[0].keys()
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Generate 'ip helper-address' configurations with validation and binary/decimal conversion")
    parser.add_argument('--input_file', required=True, help="YAML or CSV file with interface and helper_address columns")
    parser.add_argument('--output', required=True, help="CSV output file with generated configs")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ip_helpers", level=args.log_level)

    helpers = load_helpers_file(args.input_file)
    results = process_helpers(helpers, logger)

    export_to_csv(results, args.output)
    logger.info(f"IP helper configurations saved to {args.output}")

if __name__ == '__main__':
    main()
