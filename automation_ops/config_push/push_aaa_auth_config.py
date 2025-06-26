import argparse
import yaml
import csv
import re
from typing import Dict, List
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_aaa_template(template_file: str) -> List[str]:
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
        return data.get('aaa', [])


def apply_aaa_config(device: Dict[str, str], config_cmds: List[str], logger, dry_run: bool, backup: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device.get("host")
    hostname = device.get("hostname", ip)

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: AAA config commands to apply:")
        for cmd in config_cmds:
            logger.info(f"  {cmd}")
        audit_log.append({"Device": hostname, "IP": ip, "Status": "DRY-RUN"})
        return f"{ip}: DRY-RUN"

    if backup:
        try:
            ip, output = connect_device_with_retries(device, commands="show running-config")
            backup_file = f"backup_{ip.replace('.', '_')}.cfg"
            with open(backup_file, 'w') as f:
                f.write(output)
            logger.info(f"{ip}: Backup saved to {backup_file}")
        except Exception as e:
            logger.error(f"{ip}: Backup failed - {e}")

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=config_cmds,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: AAA config applied successfully.")
        audit_log.append({"Device": hostname, "IP": ip, "Status": "SUCCESS"})
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to apply AAA config - {e}")
        audit_log.append({"Device": hostname, "IP": ip, "Status": "FAILED"})
        return f"{ip}: FAILED"


def export_audit_log(audit_log: List[Dict[str, str]], path: str):
    with open(path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Device", "IP", "Status"])
        writer.writeheader()
        writer.writerows(audit_log)


def main():
    parser = argparse.ArgumentParser(description="Push AAA authentication config to devices")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--template', required=True, help="YAML AAA config template file")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--backup', action='store_true', help="Backup running-config before applying changes")
    parser.add_argument('--filter', help="Regex to filter device hostname or IP")
    parser.add_argument('--audit_csv', help="Path to save audit log CSV")
    args = parser.parse_args()

    logger = setup_logger("aaa_auth_config", level=args.log_level)
    config_cmds = load_aaa_template(args.template)
    audit_log = []

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    if args.filter:
        regex = re.compile(args.filter)
        devices = [d for d in devices if regex.search(d.get("host", "")) or regex.search(d.get("hostname", ""))]

    logger.info(f"Pushing AAA config to {len(devices)} devices...")
    for device in devices:
        result = apply_aaa_config(device, config_cmds, logger, args.dry_run, args.backup, audit_log)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit CSV saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Arguments
# - YAML inventory
# - AAA template YAML
# - Optional flags: --dry_run, --backup, --filter, --audit_csv

#2: Load AAA Config Template

#3: Load and Filter Devices
# - Validate IPs
# - If --filter is set, use regex on hostname/IP

#4: Device Loop
# - If --dry_run, log commands and mark status DRY-RUN
# - If --backup, save show running-config
# - Apply config via Netmiko
# - Log success/failure per device in audit log

#5: Output Audit
# - If --audit_csv is set, export CSV summary

#6: main()

