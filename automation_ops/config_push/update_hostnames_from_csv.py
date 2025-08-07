import argparse
import csv
from typing import Dict, List
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def load_csv_mapping(csv_path: str) -> Dict[str, str]:
    mapping = {}
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['IP']
            new_hostname = row['Hostname']
            mapping[ip] = new_hostname
    return mapping


def update_hostname(device: Dict[str, str], desired_hostname: str, logger, dry_run: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device['host']

    try:
        ip, current = connect_device_with_retries(
            device,
            commands=["show run | include hostname"],
            config_commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        if f"hostname {desired_hostname}" in current:
            logger.info(f"{ip}: Hostname already correct, skipping")
            audit_log.append({"IP": ip, "Hostname": desired_hostname, "Status": "SKIPPED"})
            return f"{ip}: SKIPPED"
    except Exception as e:
        logger.warning(f"{ip}: Unable to validate current hostname - proceeding")

    config = [f"hostname {desired_hostname}"]

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Hostname to set: {desired_hostname}")
        audit_log.append({"IP": ip, "Hostname": desired_hostname, "Status": "DRY-RUN"})
        return f"{ip}: DRY-RUN"

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=config,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: Hostname updated to {desired_hostname}")
        audit_log.append({"IP": ip, "Hostname": desired_hostname, "Status": "SUCCESS"})
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to update hostname - {e}")
        audit_log.append({"IP": ip, "Hostname": desired_hostname, "Status": "FAILED"})
        return f"{ip}: FAILED"


def export_audit(audit_data: List[Dict[str, str]], output: str):
    with open(output, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["IP", "Hostname", "Status"])
        writer.writeheader()
        writer.writerows(audit_data)


def main():
    parser = argparse.ArgumentParser(description="Update hostnames on devices from CSV mapping")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--csv', required=True, help="CSV file with IP and new Hostname")
    parser.add_argument('--audit_csv', help="Export audit log to CSV")
    parser.add_argument('--log_level', default="INFO")
    parser.add_argument('--dry_run', action='store_true')
    args = parser.parse_args()

    logger = setup_logger("update_hostname_csv", level=args.log_level)
    mapping = load_csv_mapping(args.csv)

    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d) and d['host'] in mapping]

    logger.info(f"Updating hostnames for {len(devices)} devices...")
    audit_log = []
    for device in devices:
        new_hostname = mapping[device['host']]
        result = update_hostname(device, new_hostname, logger, args.dry_run, audit_log)
        logger.info(result)

    if args.audit_csv:
        export_audit(audit_log, args.audit_csv)
        logger.info(f"Audit log saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML file
# --csv: hostname mapping (IP -> new name)
# --dry_run, --audit_csv, --log_level

#2: Load Data
# - Load hostname mapping from CSV
# - Load inventory, validate IPs, filter to matched entries

#3: For Each Device
# - Check if hostname already correct via CLI
# - If dry-run: log command
# - Else: send hostname config with Netmiko
# - Record audit log with status

#4: Export audit CSV if requested

#5: main()

