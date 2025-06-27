# connects to all devices in inventory, runs show ip arp, searches for MAC substring matches, and exports the filtered ARP entries to CSV.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_arp_table(output: str, mac_filter: str) -> List[Dict[str, str]]:
    results = []
    for line in output.splitlines():
        if re.search(mac_filter.lower(), line.lower()):
            parts = line.split()
            if len(parts) >= 4:
                results.append({
                    "IP Address": parts[0],
                    "MAC Address": parts[2],
                    "Interface": parts[3]
                })
    return results


def collect_arp_entries(device: Dict[str, str], logger, mac_filter: str) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip arp"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_arp_table(output, mac_filter)
        for entry in parsed:
            entry['Device IP'] = ip
            entry['Hostname'] = hostname
        logger.info(f"{ip}: {len(parsed)} ARP matches found")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: ARP fetch error - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "IP Address": "ERROR", "MAC Address": str(e), "Interface": ""}]


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Search ARP tables across fleet for MAC substring")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV file output")
    parser.add_argument('--mac', required=True, help="MAC substring to search (e.g. 00:1A or 001A)")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("arp_mac_search", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(collect_arp_entries(device, logger, args.mac))

    export_to_csv(results, args.output)
    logger.info(f"MAC search results written to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML device file
# --output: CSV destination
# --mac: substring to match in ARP MAC addresses
# --log_level

#2: Load & Validate Devices

#3: For Each Device
# - Run 'show ip arp'
# - Parse lines matching MAC substring
# - Extract: IP, MAC, Interface
# - Annotate with Device IP and Hostname

#4: Export results to CSV

#5: main()

