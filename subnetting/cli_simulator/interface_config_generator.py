# interface_config_generator.py

#1: Imports & Setup
# - argparse, csv, yaml, logger

#2: Load Interface Config Data
# - Load from YAML or CSV file defining interfaces, IPs, VLANs, descriptions

#3: Generate Config
# - Create CLI configuration lines for each interface

#4: Annotate Results
# - Add interface name and generated config snippet

#5: Export
# - Write generated configurations to CSV

import argparse
import csv
import yaml
from typing import List, Dict
from logger import setup_logger

def load_interface_file(file_path: str) -> List[Dict[str, str]]:
    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        interfaces = []
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                interfaces.append(row)
        return interfaces

def generate_interface_config(interface: Dict[str, str]) -> str:
    lines = [f"interface {interface['name']}"]
    if 'description' in interface:
        lines.append(f" description {interface['description']}")
    if 'vlan' in interface:
        lines.append(" switchport mode access")
        lines.append(f" switchport access vlan {interface['vlan']}")
    if 'ip_address' in interface:
        lines.append(f" ip address {interface['ip_address']} {interface.get('subnet_mask', '255.255.255.0')}")
    lines.append(" no shutdown")
    return '\n'.join(lines)

def process_interfaces(interfaces: List[Dict[str, str]], logger) -> List[Dict[str, str]]:
    results = []
    for intf in interfaces:
        config = generate_interface_config(intf)
        logger.info(f"Generated config for {intf['name']}")
        results.append({
            "Interface": intf['name'],
            "Generated Config": config
        })
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
    parser = argparse.ArgumentParser(description="Generate CLI interface configurations from YAML or CSV input")
    parser.add_argument('--input_file', required=True, help="YAML or CSV file with interface definitions")
    parser.add_argument('--output', required=True, help="CSV output file with generated configs")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("interface_config_generator", level=args.log_level)

    interfaces = load_interface_file(args.input_file)
    results = process_interfaces(interfaces, logger)

    export_to_csv(results, args.output)
    logger.info(f"Interface configurations saved to {args.output}")

if __name__ == '__main__':
    main()
