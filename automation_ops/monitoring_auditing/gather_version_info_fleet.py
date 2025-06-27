# connects to each device in the inventory, runs show version, extracts hostname, version, and model, and saves results to a CSV.

import argparse
import csv
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_version(output: str, include_serial: bool = False) -> Dict[str, str]:
    lines = output.splitlines()
    parsed = {
        "Version": "",
        "Model": "",
        "Hostname": "",
        "Serial": ""
    }
    for line in lines:
        if "Version" in line and not parsed["Version"]:
            parsed["Version"] = line.strip()
        if "Model number" in line or "Model:" in line:
            parsed["Model"] = line.strip()
        if "uptime is" in line:
            parsed["Hostname"] = line.split(" uptime is")[0].strip()
        if include_serial and ("System serial number" in line or "Processor board ID" in line):
            parsed["Serial"] = line.strip()
    return parsed


def gather_version(device: Dict[str, str], logger, include_serial: bool, filter_version: str) -> Dict[str, str]:
    ip = device['host']
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show version"],
            retries=2,
            delay=2,
            debug=False
        )
        data = parse_version(output, include_serial)
        data["IP"] = ip
        data["Compliant"] = "YES" if not filter_version or filter_version in data["Version"] else "NO"
        logger.info(f"{ip}: Version info gathered")
        return data
    except Exception as e:
        logger.error(f"{ip}: Version info failed - {e}")
        return {"IP": ip, "Hostname": "", "Model": "", "Version": f"ERROR: {e}", "Compliant": "ERROR", "Serial": "" if include_serial else ""}


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Gather version info from fleet of devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory")
    parser.add_argument('--output', required=True, help="CSV output path")
    parser.add_argument('--log_level', default="INFO")
    parser.add_argument('--filter_version', help="Optional: flag devices not matching this version")
    parser.add_argument('--include_serial', action='store_true', help="Include serial number in output")
    args = parser.parse_args()

    logger = setup_logger("version_info", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.append(gather_version(device, logger, args.include_serial, args.filter_version))

    export_to_csv(results, args.output)
    logger.info(f"Version info saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory
# --output
# --log_level
# --filter_version: match required version substring
# --include_serial: extract serial from 'show version'

#2: Load Devices & Validate

#3: For Each Device
# - Run 'show version'
# - Extract:
#     - Version
#     - Model
#     - Hostname
#     - Serial (if flag)
# - Flag 'Compliant = YES/NO' based on --filter_version

#4: Write CSV with:
# IP, Hostname, Model, Version, Compliant, Serial (optional)

