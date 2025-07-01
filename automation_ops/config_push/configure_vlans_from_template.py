import argparse
import csv
from typing import Dict, List
from pathlib import Path
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def load_vlan_template(csv_file: str, default_prefix: str) -> Dict[str, List[str]]:
    vlan_map = {}
    audit_log = []
    with open(csv_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            device = row['device']
            vlan_id = row['vlan_id']
            vlan_name = row['vlan_name'] or f"{default_prefix}{vlan_id}"
            cmd = f"vlan {vlan_id}\n name {vlan_name}"
            vlan_map.setdefault(device, []).append(cmd)
            audit_log.append({"Device": device, "VLAN_ID": vlan_id, "VLAN_Name": vlan_name})
    return vlan_map, audit_log


def apply_vlan_config(device: Dict[str, str], vlan_cmds: List[str], logger, dry_run: bool) -> str:
    ip = device.get("host")

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: VLAN commands to apply:")
        for cmd in vlan_cmds:
            logger.info(f"  {cmd.replace(chr(10), '; ')}")
        return f"{ip}: DRY-RUN"

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=vlan_cmds,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: VLAN configuration applied successfully.")
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to configure VLANs - {e}")
        return f"{ip}: FAILED"


def export_audit_log(audit_log: List[Dict[str, str]], path: str):
    with open(path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Device", "VLAN_ID", "VLAN_Name"])
        writer.writeheader()
        writer.writerows(audit_log)


def main():
    parser = argparse.ArgumentParser(description="Configure VLANs on devices from template CSV")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--csv', required=True, help="CSV template with device,vlan_id,vlan_name")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--default_prefix', default='VLAN_', help="Default prefix for missing VLAN names")
    parser.add_argument('--audit_csv', help="Path to save audit log CSV")
    args = parser.parse_args()

    logger = setup_logger("vlan_config", level=args.log_level)
    vlan_templates, audit_log = load_vlan_template(args.csv, args.default_prefix)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Applying VLAN configuration to {len(devices)} devices...")
    for device in devices:
        ip = device.get("host")
        vlan_cmds = vlan_templates.get(ip, [])
        if not vlan_cmds:
            logger.warning(f"{ip}: No VLANs defined in template, skipping.")
            continue
        result = apply_vlan_config(device, vlan_cmds, logger, args.dry_run)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit CSV saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: Parse CLI args
# - Accept inventory file, VLAN CSV, dry-run, log level, audit CSV, default name prefix

#2: Load VLAN Template
# - Build per-device VLAN command list
# - Use default prefix if name missing
# - Track all VLAN assignments in audit log

#3: Apply Config
# - For each device, apply VLAN config via Netmiko
# - Respect dry-run mode

#4: Export
# - Write audit log of Device, VLAN_ID, VLAN_Name to CSV if `--audit_csv` given

#5: Call main()

