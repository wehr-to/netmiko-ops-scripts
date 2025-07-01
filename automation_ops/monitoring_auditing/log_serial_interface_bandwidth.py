# connects to each device, extracts bandwidth values from show interfaces output for Serial interfaces, and logs the results to a CSV.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def extract_serial_bandwidth(output: str) -> List[Dict[str, str]]:
    blocks = output.split("\n\n")
    results = []
    for block in blocks:
        if "Serial" in block:
            intf_match = re.search(r"^(\S+)", block.strip())
            bw_match = re.search(r"BW (\d+) Kbit/sec", block)
            if intf_match and bw_match:
                results.append({
                    "Interface": intf_match.group(1),
                    "Bandwidth (Kbps)": bw_match.group(1)
                })
    return results


def collect_interface_data(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show interfaces"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = extract_serial_bandwidth(output)
        for item in parsed:
            item["IP"] = ip
            item["Hostname"] = hostname
        logger.info(f"{ip}: Found {len(parsed)} serial interfaces")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Error fetching serial interfaces - {e}")
        return [{"IP": ip, "Hostname": hostname, "Interface": "ERROR", "Bandwidth (Kbps)": str(e)}]


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Log serial interface bandwidth for all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("serial_bw", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(collect_interface_data(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Bandwidth data saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML file
# --output: CSV output
# --log_level

#2: Load & Validate Devices

#3: For Each Device
# - Run 'show interfaces'
# - Identify blocks for Serial interfaces
# - Parse:
#   - Interface name
#   - Bandwidth in Kbps

#4: Add IP and Hostname to each record

#5: Export full data to CSV:
# IP, Hostname, Interface, Bandwidth (Kbps)

