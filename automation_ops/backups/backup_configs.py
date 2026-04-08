import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip
import re


def backup_device_config(device: Dict[str, str], backup_dir: Path, logger, include_hostname: bool, config_type: str) -> str:
    commands = []
    if include_hostname:
        commands.append("show running-config | include hostname")
    if config_type in ["running", "both"]:
        commands.append("show running-config")
    if config_type in ["startup", "both"]:
        commands.append("show startup-config")

    ip, output = connect_device_with_retries(
        device,
        commands=commands,
        retries=3,
        delay=2,
        debug=False
    )

    if "Failed" in output or "Exception" in output:
        logger.error(f"{ip}: Backup failed: {output}")
        return f"{ip}: FAILED"

    hostname = ip.replace(".", "_")
    outputs = output.split("\n")

    if include_hostname:
        for line in outputs:
            if line.lower().startswith("hostname"):
                hostname = line.strip().split()[-1]
                break

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    index = 0
    for i, cmd in enumerate(commands):
        if "running-config" in cmd:
            config = "\n".join(outputs[index:]).strip()
            if config:
                suffix = "running" if "running" in cmd else "startup"
                filename = backup_dir / f"{hostname}_{suffix}_config_{timestamp}.txt"
                filename.write_text(config)
                logger.info(f"{ip}: {suffix} config backed up to {filename}")
            index = len(outputs)  # Avoid writing again

    return f"{ip}: SUCCESS"


def main():
    parser = argparse.ArgumentParser(description="Backup device running/startup configs")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--backup_dir', default="backups", help="Directory to store config backups")
    parser.add_argument('--include_hostname', action='store_true', help="Use hostname in filename")
    parser.add_argument('--config_type', choices=["running", "startup", "both"], default="running", help="Which config(s) to backup")
    args = parser.parse_args()

    logger = setup_logger("config_backup", level=args.log_level)
    backup_path = Path(args.backup_dir)
    backup_path.mkdir(parents=True, exist_ok=True)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Starting config backup for {len(devices)} devices...")
    for device in devices:
        status = backup_device_config(device, backup_path, logger, args.include_hostname, args.config_type)
        logger.info(status)


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - Import logger, inventory loader, Netmiko connector
# - Add Path, re, datetime for file management and hostname parsing

#2: Device Config Backup Function
# - Build command list based on `--config_type` and `--include_hostname`
# - Use Netmiko to run all commands in one session
# - Extract hostname from output if flag set
# - Save each config (running/startup) with timestamp
# - Name files by IP or hostname

#3: CLI and Main Logic
# - Parse CLI args: inventory, log level, output dir, config type, include hostname
# - Load and validate devices
# - Create output dir
# - Iterate devices and run backup
# - Log results for each device

#4: Entry Point
# - main()

