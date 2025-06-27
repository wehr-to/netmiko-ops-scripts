# connects to devices, runs OSPF/EIGRP/BGP neighbor commands, parses neighbors, and exports a consolidated CSV report.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_routing_neighbors(output: str) -> List[Dict[str, str]]:
    neighbors = []
    for line in output.splitlines():
        match = re.search(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)", line)
        if match:
            neighbors.append({
                "Protocol": match.group(1),
                "Neighbor IP": match.group(2),
                "AS": match.group(3),
                "Uptime": match.group(4),
                "State": match.group(5)
            })
    return neighbors


def collect_neighbors(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip ospf neighbor", "show ip eigrp neighbor", "show ip bgp summary"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        neighbors = parse_routing_neighbors(output)
        for n in neighbors:
            n['Device IP'] = ip
            n['Hostname'] = hostname
        logger.info(f"{ip}: Found {len(neighbors)} neighbors")
        return neighbors
    except Exception as e:
        logger.error(f"{ip}: Routing neighbor detection failed - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Neighbor IP": "ERROR", "Protocol": "", "AS": "", "Uptime": "", "State": str(e)}]


def export_neighbors(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Detect routing neighbors across protocols")
    parser.add_argument('--inventory', required=True, help="YAML inventory")
    parser.add_argument('--output', required=True, help="CSV output path")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("routing_neighbors", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(collect_neighbors(device, logger))

    export_neighbors(results, args.output)
    logger.info(f"Routing neighbors export completed: {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML inventory
# --output: path to CSV
# --log_level

#2: Load Inventory
# - Validate IPs

#3: For Each Device
# - Run: show ip ospf neighbor
# - Run: show ip eigrp neighbor
# - Run: show ip bgp summary
# - Extract neighbor IPs, states, uptime, protocol
# - Tag with hostname + IP

#4: Export to CSV

#5: main()
