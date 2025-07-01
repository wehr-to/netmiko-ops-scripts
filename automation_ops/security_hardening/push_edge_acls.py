# push_edge_acls.py

#1: Imports & Setup
# - argparse, csv, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Filter to edge routers by tag or hostname

#3: Load ACL Commands
# - Load edge ACL config lines from a file

#4: Connect & Push ACL
# - Push ACL to each edge router using Netmiko config mode

#5: Export
# - Write push results to CSV

import argparse
import csv
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def load_acl_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("!")]

def filter_edge_devices(devices: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [d for d in devices if 'edge' in d.get('role', '').lower() or 'edge' in d.get('hostname', '').lower()]

def push_acl_to_device(device: Dict[str, str], acl_lines: List[str], logger) -> Dict[str, str]:
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
        output = connection.send_config_set(acl_lines)
        connection.save_config()
        connection.disconnect()
        return {"Device IP": ip, "Hostname": hostname, "Status": "Success"}
    except Exception as e:
        logger.error(f"{ip}: Failed to push edge ACL - {e}")
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
    parser = argparse.ArgumentParser(description="Push edge ACL to edge devices via Netmiko")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--acl', required=True, help="Edge ACL file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("push_edge_acls", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]
    edge_devices = filter_edge_devices(devices)
    acl_lines = load_acl_file(args.acl)

    results = []
    for device in edge_devices:
        results.append(push_acl_to_device(device, acl_lines, logger))

    export_to_csv(results, args.output)
    logger.info(f"Edge ACL push results saved to {args.output}")

if __name__ == '__main__':
    main()
