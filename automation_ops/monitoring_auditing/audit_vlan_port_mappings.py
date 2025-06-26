# connects to switches, parses show vlan brief output, extracts VLAN-to-port assignments, and exports them to CSV.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_vlan_interfaces(output: str) -> List[Dict[str, str]]:
    vlan_data = []
    for line in output.splitlines():
        match = re.search(r"^(?P<VLAN>\d+)\s+(?P<Name>\S+)\s+active\s+(?P<Ports>.+)$", line.strip())
        if match:
            ports = match.group("Ports").split(',')
            for port in ports:
                vlan_data.append({
                    "VLAN": match.group("VLAN"),
                    "Name": match.group("Name"),
                    "Port": port.strip()
                })
    return vlan_data


def collect_vlan_port_mappings(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show vlan brief"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        vlan_entries = parse_vlan_interfaces(output)
        for entry in vlan_entries:
            entry["IP"] = ip
            entry["Hostname"] = hostname
        logger.info(f"{ip}: Collected {len(vlan_entries)} VLAN-port mappings.")
        return vlan_entries
    except Exception as e:
        logger.error(f"{ip}: Failed to collect VLAN data - {e}")
        return [{"IP": ip, "Hostname": hostname, "VLAN": "ERROR", "Name": "", "Port": "", "Error": str(e)}]


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Audit VLAN to port mappings on network devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file path")
    parser.add_argument('--output', required=True, help="CSV export file path")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("vlan_audit", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(collect_vlan_port_mappings(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"VLAN audit CSV saved to: {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML file
# --output: CSV file
# --log_level

#2: Load Devices
# - Validate IPs

#3: For Each Device
# - Run 'show vlan brief'
# - Parse VLAN ID, name, associated ports
# - Tag with IP and hostname

#4: Export to CSV

#5: main()

