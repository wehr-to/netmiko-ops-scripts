import argparse
import csv
import re
from typing import List, Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def extract_serial(output: str) -> str:
    match = re.search(r"System [Ss]erial [Nn]umber\s*:\s*(\S+)", output)
    return match.group(1) if match else "NOT FOUND"


def get_serial_from_device(device: Dict[str, str], logger) -> Dict[str, str]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show version"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        serial = extract_serial(output)
        logger.info(f"{ip}: Serial number parsed successfully.")
        return {"IP": ip, "Hostname": hostname, "Serial": serial, "Status": "SUCCESS"}
    except Exception as e:
        logger.error(f"{ip}: Failed to retrieve serial - {e}")
        return {"IP": ip, "Hostname": hostname, "Serial": "ERROR", "Status": f"FAILED: {e}"}


def export_serials_to_csv(serials: List[Dict[str, str]], csv_path: str):
    fields = ["IP", "Hostname", "Serial", "Status"]
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(serials)


def main():
    parser = argparse.ArgumentParser(description="Parse serial numbers for asset tracking")
    parser.add_argument('--inventory', required=True, help="Path to YAML inventory file")
    parser.add_argument('--output', required=True, help="Path to export CSV")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("serial_parser", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        result = get_serial_from_device(device, logger)
        results.append(result)

    export_serials_to_csv(results, args.output)
    logger.info(f"Serial export complete: {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML device list
# --output: path to write CSV
# --log_level

#2: Load & Validate Devices
# - Ensure IP validity

#3: For Each Device
# - Run 'show version'
# - Parse serial number using regex
# - Store IP, hostname, serial, status

#4: Export CSV

#5: main()


