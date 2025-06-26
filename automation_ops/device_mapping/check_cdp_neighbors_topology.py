# Check CDP neighbors across a topology

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_cdp_neighbors(output: str) -> List[Dict[str, str]]:
    neighbors = []
    lines = output.splitlines()
    for line in lines:
        match = re.search(r"(\S+)\s+(\d+)\s+(\S+ \S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            neighbors.append({
                "Device ID": match.group(1),
                "Local Intf": match.group(3),
                "Holdtime": match.group(2),
                "Capability": match.group(4),
                "Platform": match.group(5),
                "Port ID": match.group(6),
                "Mgmt IP": match.group(7)
            })
    return neighbors


def get_cdp_neighbors(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show cdp neighbors detail"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_cdp_neighbors(output)
        logger.info(f"{ip}: Parsed {len(parsed)} neighbors.")
        for neighbor in parsed:
            neighbor["IP"] = ip
            neighbor["Hostname"] = hostname
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to get CDP neighbors - {e}")
        return [{"IP": ip, "Hostname": hostname, "Error": str(e)}]


def export_topology_to_csv(data: List[Dict[str, str]], csv_path: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Check CDP neighbor topology")
    parser.add_argument('--inventory', required=True, help="YAML inventory")
    parser.add_argument('--output', required=True, help="Output CSV")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("cdp_topology", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    all_neighbors = []
    for device in devices:
        neighbors = get_cdp_neighbors(device, logger)
        all_neighbors.extend(neighbors)

    export_topology_to_csv(all_neighbors, args.output)
    logger.info(f"CDP topology saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML device list
# --output: CSV path
# --log_level

#2: Load & Validate Devices
# - Ensure valid IPs

#3: For Each Device
# - Run 'show cdp neighbors detail'
# - Parse Device ID, Local Intf, Port ID, Platform, etc.
# - Tag with device IP and hostname

#4: Export to CSV
# - Write all parsed neighbor links

#5: main()
