import argparse
from pathlib import Path
from datetime import datetime
import gzip
import re
from typing import Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def backup_running_config(device: Dict[str, str], backup_dir: Path, logger, pattern: str) -> str:
    ip = device.get("host")
    hostname = device.get("hostname", ip)

    if pattern and not re.search(pattern, ip) and not re.search(pattern, hostname):
        logger.info(f"{ip}: Skipped due to pattern mismatch")
        return f"{ip}: SKIPPED"

    ip, output = connect_device_with_retries(
        device,
        commands=["show running-config"],
        retries=3,
        delay=2,
        debug=False
    )

    if "Failed" in output or "Exception" in output:
        logger.error(f"{ip}: Backup failed: {output}")
        return f"{ip}: FAILED"

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = backup_dir / f"{ip.replace('.', '_')}_running_config_{timestamp}.txt.gz"

    with gzip.open(filename, 'wt') as f:
        f.write(output)

    logger.info(f"{ip}: Running config backed up to {filename}")
    return f"{ip}: SUCCESS"


def main():
    parser = argparse.ArgumentParser(description="Backup running-configs from devices")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--backup_dir', default="backups", help="Directory to store config backups")
    parser.add_argument('--pattern', default='', help="Regex pattern to match IP or hostname")
    args = parser.parse_args()

    logger = setup_logger("running_config_backup", level=args.log_level)
    backup_path = Path(args.backup_dir)
    backup_path.mkdir(parents=True, exist_ok=True)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Starting running-config backup for {len(devices)} devices...")
    for device in devices:
        status = backup_running_config(device, backup_path, logger, args.pattern)
        logger.info(status)


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - Import gzip, regex, argparse, datetime, pathlib, logging modules

#2: Filter and Backup Logic
# - If device IP or hostname doesn't match `--pattern`, skip
# - Connect and retrieve `show running-config`
# - Save output as gzip file with timestamped name

#3: CLI Parser
# - Accept `--file`, `--log_level`, `--backup_dir`, and `--pattern` options

#4: Execution Loop
# - Load and validate devices
# - Filter and back up configs with compression
# - Log per-device result

#5: Entry Point
# - Call main()

