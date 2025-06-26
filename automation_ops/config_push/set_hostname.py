import argparse
import yaml
import re
import csv
from typing import Dict, List
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_hostname_map(csv_path: str) -> Dict[str, str]:
    hostname_map = {}
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['IP']
            hostname = row['Hostname']
            hostname_map[ip] = hostname
    return hostname_map


def apply_hostname_config(device: Dict[str, str], new_hostname: str, logger, dry_run: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device.get("host")

    try:
        ip, current_hostname = connect_device_with_retries(
            device,
            commands=["show running-config | include hostname"],
            config_commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        match = re.search(r"hostname (\S+)", current_hostname)
        if match and match.group(1) == new_hostname:
            logger.info(f"{ip}: Hostname already set to {new_hostname}, skipping.")
            audit_log.append({"IP": ip, "Hostname": new_hostname, "Status": "SKIPPED"})
            return f"{ip}: SKIPPED"
    except Exception as e:
        logger.warning(f"{ip}: Unable to verify current hostname - proceeding anyway")

    config_cmds = [f"hostname {new_hostname}"]

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Hostname to set: {new_hostname}")
        audit_log.append({"IP": ip, "Hostname": new_hostname, "Status": "DRY-RUN"})
        return f"{ip}: DRY-RUN"

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=config_cmds,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: Hostname set to {new_hostname} successfully.")
        audit_log.append({"IP": ip, "Hostname": new_hostname, "Status": "SUCCESS"})
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to set hostname - {e}")
        audit_log.append({"IP": ip, "Hostname": new_hostname, "Status": "FAILED"})
        return f"{ip}: FAILED"


def export_audit_log(audit_data: List[Dict[str, str]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["IP", "Hostname", "Status"])
        writer.writeheader()
        writer.writerows(audit_data)


def main():
    parser = argparse.ArgumentParser(description="Set hostname on network devices")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--hostname_csv', required=True, help="CSV file with IP and new Hostname")
    parser.add_argument('--append_domain', help="Optional domain to append to hostname (e.g. .corp.local)")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview changes without applying")
    parser.add_argument('--filter', help="Regex to filter devices by IP")
    parser.add_argument('--audit_csv', help="Path to export audit CSV log")
    args = parser.parse_args()

    logger = setup_logger("set_hostname", level=args.log_level)
    hostname_map = load_hostname_map(args.hostname_csv)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    if args.filter:
        regex = re.compile(args.filter)
        devices = [d for d in devices if regex.search(d['host'])]

    logger.info(f"Setting hostname on {len(devices)} devices...")
    audit_log = []
    for device in devices:
        ip = device.get("host")
        if ip in hostname_map:
            desired_hostname = hostname_map[ip]
            if args.append_domain:
                desired_hostname += args.append_domain
            result = apply_hostname_config(device, desired_hostname, logger, args.dry_run, audit_log)
            logger.info(result)
        else:
            logger.warning(f"{ip}: No hostname found in CSV mapping")
            audit_log.append({"IP": ip, "Hostname": "N/A", "Status": "SKIPPED"})

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit log saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --file: inventory
# --hostname_csv: hostname mappings
# --append_domain: optional domain suffix
# --dry_run, --filter, --audit_csv

#2: Load Hostname Mapping
# - Read IP/hostname pairs from CSV
# - Append domain if --append_domain set

#3: Load & Filter Devices
# - Validate IPs
# - Filter by regex

#4: For Each Device
# - Fetch current hostname
# - If already matches desired, skip
# - Else: build 'hostname <>' command
# - If dry-run: log only
# - Else: push via Netmiko
# - Record audit log

#5: Export Audit CSV (if provided)

#6: main()

