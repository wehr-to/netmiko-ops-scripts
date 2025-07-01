import argparse
import yaml
import re
import csv
from typing import Dict, List
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_logging_template(template_file: str) -> List[str]:
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
        return data.get('logging', [])


def backup_logging_config(device: Dict[str, str], logger) -> None:
    ip = device.get("host")
    try:
        ip, output = connect_device_with_retries(device, commands="show run | include logging")
        with open(f"backup_logging_{ip.replace('.', '_')}.log", 'w') as f:
            f.write(output)
        logger.info(f"{ip}: Backup saved.")
    except Exception as e:
        logger.error(f"{ip}: Backup failed - {e}")


def apply_logging_config(device: Dict[str, str], config_cmds: List[str], logger, dry_run: bool, backup: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device.get("host")
    hostname = device.get("hostname", ip)

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Logging config commands to apply:")
        for cmd in config_cmds:
            logger.info(f"  {cmd}")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "DRY-RUN", "Commands": len(config_cmds)})
        return f"{ip}: DRY-RUN"

    if backup:
        backup_logging_config(device, logger)

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=config_cmds,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: Logging server config applied successfully.")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "SUCCESS", "Commands": len(config_cmds)})
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to apply logging config - {e}")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "FAILED", "Commands": len(config_cmds)})
        return f"{ip}: FAILED"


def export_audit_log(audit_data: List[Dict[str, str]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["IP", "Hostname", "Status", "Commands"])
        writer.writeheader()
        writer.writerows(audit_data)


def main():
    parser = argparse.ArgumentParser(description="Push logging server config to devices")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--template', required=True, help="YAML template file with 'logging' key")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--filter', help="Regex to filter devices by IP or hostname")
    parser.add_argument('--backup', action='store_true', help="Backup existing logging config before changes")
    parser.add_argument('--audit_csv', help="Path to save audit CSV log")
    args = parser.parse_args()

    logger = setup_logger("push_logging", level=args.log_level)
    config_cmds = load_logging_template(args.template)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    if args.filter:
        regex = re.compile(args.filter)
        devices = [d for d in devices if regex.search(d.get("host", "")) or regex.search(d.get("hostname", ""))]

    logger.info(f"Pushing logging server config to {len(devices)} devices...")
    audit_log = []
    for device in devices:
        result = apply_logging_config(device, config_cmds, logger, args.dry_run, args.backup, audit_log)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit log saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Arguments
# - Inventory file, logging template, log level
# - --dry_run: preview only
# - --filter: apply to matching hostnames/IPs
# - --backup: save pre-change logging config
# - --audit_csv: export per-device results

#2: Load Template
# - Parse logging commands from YAML

#3: Load & Filter Devices
# - Validate IPs
# - Apply regex filter if needed

#4: For Each Device
# - If dry-run: log commands
# - If backup: run show run | include logging and save
# - Push config using Netmiko
# - Append to audit log with status and number of commands

#5: Export Audit CSV
# - If audit path given, save summary

#6: Call main()

