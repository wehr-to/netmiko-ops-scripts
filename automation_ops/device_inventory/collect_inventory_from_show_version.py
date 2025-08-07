import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_show_version(output: str) -> Dict[str, str]:
    parsed = {}
    model_match = re.search(r"Model number\s*:\s*(\S+)", output)
    version_match = re.search(r"Version\s+(\S+),", output)
    serial_match = re.search(r"System serial number\s*:\s*(\S+)", output)

    if model_match:
        parsed["Model"] = model_match.group(1)
    if version_match:
        parsed["Version"] = version_match.group(1)
    if serial_match:
        parsed["Serial"] = serial_match.group(1)

    return parsed


def collect_inventory(device: Dict[str, str], logger, results: List[Dict[str, str]]) -> None:
    ip = device["host"]
    hostname = device.get("hostname", ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show version"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_show_version(output)
        parsed.update({"IP": ip, "Hostname": hostname, "Status": "SUCCESS"})
        logger.info(f"{ip}: Inventory collected")
    except Exception as e:
        parsed = {"IP": ip, "Hostname": hostname, "Status": f"ERROR: {e}"}
        logger.error(f"{ip}: Failed to collect inventory - {e}")
    results.append(parsed)


def export_to_csv(data: List[Dict[str, str]], output: str):
    fields = ["IP", "Hostname", "Model", "Version", "Serial", "Status"]
    with open(output, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Collect device inventory from show version")
    parser.add_argument('--inventory', required=True, help="Path to YAML inventory")
    parser.add_argument('--output', required=True, help="Output CSV file path")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("collect_inventory", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        collect_inventory(device, logger, results)

    export_to_csv(results, args.output)
    logger.info(f"Inventory CSV saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML input
# --output: path to save CSV
# --log_level

#2: Load Devices
# - Validate IPs

#3: For Each Device
# - Run 'show version' via Netmiko
# - Parse model/version/serial via regex
# - Log status and add to results list

#4: Write results to CSV

#5: main()


