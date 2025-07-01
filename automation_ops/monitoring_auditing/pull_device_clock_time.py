# connects to all devices, runs show clock, and exports timestamp data to a CSV.

import argparse
import csv
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def parse_clock_output(output: str) -> str:
    lines = output.strip().splitlines()
    return lines[0] if lines else "No output"


def fetch_device_clock(device: Dict[str, str], logger) -> Dict[str, str]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show clock"],
            retries=2,
            delay=2,
            debug=False
        )
        clock = parse_clock_output(output)
        logger.info(f"{ip}: Clock pulled")
        return {"IP": ip, "Hostname": hostname, "Clock": clock}
    except Exception as e:
        logger.error(f"{ip}: Clock fetch failed - {e}")
        return {"IP": ip, "Hostname": hostname, "Clock": f"ERROR: {e}"}


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = ["IP", "Hostname", "Clock"]
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Pull current clock time from all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output path")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("device_clock", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.append(fetch_device_clock(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Clock results saved to {args.output}")


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - Import argparse, CSV, YAML parser, logger, Netmiko connector

#2: Load & Validate Inventory
# - Load devices from YAML
# - Validate IPs

#3: Connect & Collect
# - Run 'show clock'
# - Extract first line of output

#4: Output Handling
# - Append device IP, hostname, and clock result to list

#5: Export
# - Write results to CSV with headers: IP, Hostname, Clock
