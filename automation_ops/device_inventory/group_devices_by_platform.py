import argparse
import yaml
import csv
from collections import defaultdict
from typing import Dict, List
from pathlib import Path
from logger import setup_logger


def load_inventory(file_path: str) -> List[Dict[str, str]]:
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def group_by_platform(devices: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    platform_groups = defaultdict(list)
    for device in devices:
        platform = device.get('device_type', 'unknown')
        platform_groups[platform].append(device)
    return platform_groups


def export_grouped_inventory(groups: Dict[str, List[Dict[str, str]]], output_dir: str, logger):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    for platform, devices in groups.items():
        path = Path(output_dir) / f"{platform}_devices.csv"
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["host", "username", "device_type"])
            writer.writeheader()
            for device in devices:
                writer.writerow({
                    "host": device.get("host"),
                    "username": device.get("username"),
                    "device_type": device.get("device_type")
                })
        logger.info(f"Exported {len(devices)} devices to {path}")


def main():
    parser = argparse.ArgumentParser(description="Group devices by platform type")
    parser.add_argument('--inventory', required=True, help="Path to YAML inventory file")
    parser.add_argument('--output_dir', default="grouped_output", help="Directory to export grouped CSVs")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("group_by_platform", level=args.log_level)
    devices = load_inventory(args.inventory)
    logger.info(f"Loaded {len(devices)} devices from inventory")

    grouped = group_by_platform(devices)
    export_grouped_inventory(grouped, args.output_dir, logger)
    logger.info("Grouping completed.")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: input YAML
# --output_dir: export directory
# --log_level

#2: Load Inventory
# - Read list of devices from YAML

#3: Group Devices
# - Group into dict keyed by 'device_type'

#4: Export Groups
# - For each platform:
#   - write CSV with host, username, device_type

#5: Log completion
#6: main()
