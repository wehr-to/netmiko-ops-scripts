# tag_vlan_interfaces.py

#1: Imports & Setup
# - argparse, csv, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Load VLAN ID and Interfaces
# - Load VLAN ID and list of interfaces from CLI or file

#4: Connect & Tag Interfaces
# - Configure interfaces to tag (switchport access vlan X) using Netmiko

#5: Export
# - Write tagging results to CSV

import argparse
import csv
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def generate_tag_commands(vlan_id: str, interfaces: List[str]) -> List[str]:
    commands = []
    for interface in interfaces:
        commands.extend([
            f"interface {interface}",
            "switchport mode access",
            f"switchport access vlan {vlan_id}",
            "no shutdown"
        ])
    return commands

def tag_interfaces_on_device(device: Dict[str, str], tag_commands: List[str], logger) -> Dict[str, str]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        connection = connect_device_with_retries(
            device,
            commands=[],
            retries=2,
            delay=2,
            debug=False,
            return_conn=True
        )
        connection.send_config_set(tag_commands)
        connection.save_config()
        connection.disconnect()
        return {"Device IP": ip, "Hostname": hostname, "Status": "Interfaces Tagged"}
    except Exception as e:
        logger.error(f"{ip}: Failed to tag interfaces - {e}")
        return {"Device IP": ip, "Hostname": hostname, "Status": f"ERROR - {e}"}

def load_interfaces_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("!")]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Tag VLAN to interfaces on devices via Netmiko")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--vlan_id', required=True, help="VLAN ID to tag")
    parser.add_argument('--interfaces_file', required=True, help="File with list of interfaces to tag")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("tag_vlan_interfaces", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    interfaces = load_interfaces_file(args.interfaces_file)
    tag_commands = generate_tag_commands(args.vlan_id, interfaces)

    results = []
    for device in devices:
        results.append(tag_interfaces_on_device(device, tag_commands, logger))

    export_to_csv(results, args.output)
    logger.info(f"VLAN interface tagging results saved to {args.output}")

if __name__ == '__main__':
    main()

