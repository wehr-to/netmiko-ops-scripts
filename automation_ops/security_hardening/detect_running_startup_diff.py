# detect_running_startup_diff.py

#1: Imports & Setup
# - argparse, csv, re, logger, Netmiko conn, YAML parser

#2: Load & Validate Inventory
# - Load YAML devices
# - Validate IPs

#3: Connect & Parse
# - Run 'show running-config | redirect flash:run_cfg'
# - Run 'show startup-config | redirect flash:start_cfg'
# - Compare the two saved configs for differences

#4: Annotate Results
# - Add IP, Hostname, and whether configs match or not

#5: Export
# - Write diff check results to CSV

import argparse
import csv
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip

def check_config_diff(output: str) -> List[Dict[str, str]]:
    configs_match = "startup config is not present" not in output.lower() and "startup config is same as running config" in output.lower()
    return [{
        "Configs Match": "Yes" if configs_match else "No"
    }]

def audit_config_consistency(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show archive config differences system:running-config nvram:startup-config"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = check_config_diff(output)
        for item in parsed:
            item['Device IP'] = ip
            item['Hostname'] = hostname
        logger.info(f"{ip}: Config consistency check complete")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Failed to check config consistency - {e}")
        return [{"Device IP": ip, "Hostname": hostname, "Configs Match": f"ERROR - {e}"}]

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Detect running vs startup config differences on all devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("config_diff_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(audit_config_consistency(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"Running vs startup config diff saved to {args.output}")

if __name__ == '__main__':
    main()
