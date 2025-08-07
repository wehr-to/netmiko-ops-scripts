# create_vlan.py

#1: Imports & Setup
# - argparse, csv, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Load VLAN Config
# - Load VLAN ID and Name from CLI or file

#4: Connect & Push VLAN
# - Create VLAN with specified ID and Name on each device using Netmiko config mode

#5: Export
# - Write VLAN creation results to CSV

import argparse
import csv
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def generate_vlan_commands(vlan_id: str, vlan_name: str) -> List[str]:
    return [
        f"vlan {vlan_id}",
        f"name {vlan_name}"
    ]

def push_vlan_to_device(device: Dict[str, str], vlan_commands: List[str], logger) -> Dict[str, str]:
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
        connection.send_config_set(vlan_commands)
        connection.save_config()
        connection.disconnect()
        return {"Device IP": ip, "Hostname": hostname, "Status": "VLAN Created"}
    except Exception as e:
        logger.error(f"{ip}: Failed to create VLAN - {e}")
        return {"Device IP": ip, "Hostname": hostname, "Status": f"ERROR - {e}"}

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Create VLAN on all devices via Netmiko")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--vlan_id', required=True, help="VLAN ID to create")
    parser.add_argument('--vlan_name', required=True, help="VLAN Name to assign")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("create_vlan", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    vlan_commands = generate_vlan_commands(args.vlan_id, args.vlan_name)

    results = []
    for device in devices:
        results.append(push_vlan_to_device(device, vlan_commands, logger))

    export_to_csv(results, args.output)
    logger.info(f"VLAN creation results saved to {args.output}")

if __name__ == '__main__':
    main()

