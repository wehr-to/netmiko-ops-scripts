import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def parse_mac_table(output: str) -> List[Dict[str, str]]:
    mac_entries = []
    for line in output.splitlines():
        match = re.search(r"(?P<MAC>[0-9a-f.:-]{14,20})\s+(?P<Type>\S+)\s+(?P<Ports>\S+)", line, re.IGNORECASE)
        if match:
            mac_entries.append({
                "MAC": match.group("MAC"),
                "Type": match.group("Type"),
                "Port": match.group("Ports")
            })
    return mac_entries


def get_mac_table(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show mac address-table"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        entries = parse_mac_table(output)
        for entry in entries:
            entry["IP"] = ip
            entry["Hostname"] = hostname
        logger.info(f"{ip}: Parsed {len(entries)} MAC entries")
        return entries
    except Exception as e:
        logger.error(f"{ip}: Failed to retrieve MAC table - {e}")
        return [{"IP": ip, "Hostname": hostname, "MAC": "ERROR", "Type": "", "Port": "", "Error": str(e)}]


def export_mac_to_csv(data: List[Dict[str, str]], csv_path: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Export MAC address tables for endpoint mapping")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV export path")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("mac_export", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(get_mac_table(device, logger))

    export_mac_to_csv(results, args.output)
    logger.info(f"MAC table export complete: {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML device list
# --output: CSV file path
# --log_level

#2: Load & Validate Inventory
# - Validate IPs

#3: For Each Device
# - Run 'show mac address-table'
# - Extract MAC, type, port
# - Append IP, hostname

#4: Export All Results to CSV

#5: main()

