import argparse
import csv
import ipaddress
from typing import Dict, List
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_interface_ip_map(csv_file: str, validate: bool) -> (Dict[str, List[str]], List[Dict[str, str]]):
    ip_map = {}
    audit_log = []
    with open(csv_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            device = row['device']
            interface = row['interface']
            ip_address = row['ip_address']
            netmask = row.get('netmask', '')
            shutdown = row.get('shutdown', '').lower() == 'yes'

            if validate:
                try:
                    ipaddress.ip_interface(f"{ip_address}/{netmask if netmask else '24'}")
                except ValueError:
                    continue

            cmd = [f"interface {interface}", f"ip address {ip_address} {netmask}".strip()]
            cmd.append("shutdown" if shutdown else "no shutdown")
            ip_map.setdefault(device, []).append('\n '.join(cmd))
            audit_log.append({"Device": device, "Interface": interface, "IP": ip_address, "Mask": netmask, "Shutdown": str(shutdown).upper(), "Status": "PENDING"})
    return ip_map, audit_log


def apply_interface_ips(device: Dict[str, str], ip_cmds: List[str], logger, dry_run: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device.get("host")

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Interface IP commands to apply:")
        for cmd in ip_cmds:
            logger.info(f"  {cmd.replace(chr(10), '; ')}")
        for row in audit_log:
            if row["Device"] == ip:
                row["Status"] = "DRY-RUN"
        return f"{ip}: DRY-RUN"

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=ip_cmds,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        for row in audit_log:
            if row["Device"] == ip:
                row["Status"] = "SUCCESS"
        logger.info(f"{ip}: Interface IPs deployed successfully.")
        return f"{ip}: SUCCESS"
    except Exception as e:
        for row in audit_log:
            if row["Device"] == ip:
                row["Status"] = "FAILED"
        logger.error(f"{ip}: Failed to deploy interface IPs - {e}")
        return f"{ip}: FAILED"


def export_audit_log(audit_log: List[Dict[str, str]], path: str):
    with open(path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Device", "Interface", "IP", "Mask", "Shutdown", "Status"])
        writer.writeheader()
        writer.writerows(audit_log)


def main():
    parser = argparse.ArgumentParser(description="Deploy interface IPs to devices via template")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--csv', required=True, help="CSV with device,interface,ip_address[,netmask,shutdown]")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--validate_ips', action='store_true', help="Validate IP format before applying")
    parser.add_argument('--audit_csv', help="Path to export audit log CSV")
    args = parser.parse_args()

    logger = setup_logger("interface_ips", level=args.log_level)
    ip_template, audit_log = load_interface_ip_map(args.csv, args.validate_ips)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Deploying interface IPs to {len(devices)} devices...")
    for device in devices:
        ip = device.get("host")
        ip_cmds = ip_template.get(ip, [])
        if not ip_cmds:
            logger.warning(f"{ip}: No IP assignments found, skipping.")
            continue
        result = apply_interface_ips(device, ip_cmds, logger, args.dry_run, audit_log)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit CSV saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: Parse CLI Arguments
# - YAML inventory file
# - CSV template with interface IP mappings
# - Flags: --dry_run, --audit_csv, --validate_ips

#2: Load Interface IP CSV
# - For each row, build config commands:
#   - interface <intf>
#   - ip address <ip> <mask>
#   - shutdown / no shutdown
# - If --validate_ips, reject invalid addresses
# - Store rows in an audit log with initial status

#3: Load Devices
# - Load YAML and validate IPs

#4: Apply Config
# - For each device:
#   - Skip if no commands
#   - If dry-run, print and mark audit
#   - Else push config, mark audit as SUCCESS/FAILED

#5: Export CSV
# - If --audit_csv provided, write Device, Interface, IP, Mask, Shutdown, Status

#6: Entry
# - Call main()

