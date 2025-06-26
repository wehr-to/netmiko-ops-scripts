# connects to devices, runs show interfaces status, and flags interfaces with non-full duplex or problematic speeds. Results are exported to CSV.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_interface_status(output: str) -> List[Dict[str, str]]:
    mismatches = []
    for line in output.splitlines():
        match = re.search(r"^(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            intf, speed, duplex, status = match.group(1), match.group(2), match.group(3), match.group(4)
            if duplex.lower() != 'full' or speed.lower() == 'a-100' or speed.lower().startswith('half'):
                mismatches.append({
                    "Interface": intf,
                    "Speed": speed,
                    "Duplex": duplex,
                    "Status": status
                })
    return mismatches


def check_duplex_mismatches(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show interfaces status"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_interface_status(output)
        for entry in parsed:
            entry["IP"] = ip
            entry["Hostname"] = hostname
        logger.info(f"{ip}: Found {len(parsed)} possible duplex/speed mismatches")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Interface status check failed - {e}")
        return [{"IP": ip, "Hostname": hostname, "Interface": "ERROR", "Speed": "", "Duplex": "", "Status": str(e)}]


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Detect duplex/speed mismatches across devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output path")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("duplex_mismatch", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(check_duplex_mismatches(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Duplex/speed mismatch audit saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML input
# --output: path to save results
# --log_level

#2: Load Devices
# - Validate IPs

#3: For Each Device
# - Run 'show interfaces status'
# - Parse interface, speed, duplex, status
# - Flag mismatches (non-full duplex, ambiguous speeds)

#4: Export to CSV

#5: main()
