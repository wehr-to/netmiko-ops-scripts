import argparse
import csv
from typing import Dict, List
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def generate_description_commands(descriptions: Dict[str, str], clear: bool = False) -> List[str]:
    commands = []
    for iface, desc in descriptions.items():
        if clear:
            commands.append(f"interface {iface}\n no description")
        else:
            commands.append(f"interface {iface}\n description {desc}")
    return commands


def apply_interface_descriptions(device: Dict[str, str], logger, dry_run: bool, clear: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device.get("host")
    iface_descriptions = device.get("interface_descriptions", {})

    if not iface_descriptions:
        logger.warning(f"{ip}: No interface_descriptions found, skipping.")
        return f"{ip}: SKIPPED"

    commands = generate_description_commands(iface_descriptions, clear=clear)

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Commands to apply:")
        for cmd in commands:
            logger.info(f"  {cmd.replace(chr(10), '; ')}")
        for iface, desc in iface_descriptions.items():
            audit_log.append({"Device": ip, "Interface": iface, "Description": desc if not clear else "CLEARED", "Status": "DRY-RUN"})
        return f"{ip}: DRY-RUN"

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=commands,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        for iface, desc in iface_descriptions.items():
            audit_log.append({"Device": ip, "Interface": iface, "Description": desc if not clear else "CLEARED", "Status": "SUCCESS"})
        logger.info(f"{ip}: Applied interface descriptions to {len(iface_descriptions)} interfaces.")
        return f"{ip}: SUCCESS"
    except Exception as e:
        for iface, desc in iface_descriptions.items():
            audit_log.append({"Device": ip, "Interface": iface, "Description": desc if not clear else "CLEARED", "Status": "FAILED"})
        logger.error(f"{ip}: Failed to apply interface descriptions - {e}")
        return f"{ip}: FAILED"


def export_audit_log(audit_log: List[Dict[str, str]], path: str):
    with open(path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Device", "Interface", "Description", "Status"])
        writer.writeheader()
        writer.writerows(audit_log)


def main():
    parser = argparse.ArgumentParser(description="Bulk Interface Description Application Tool")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Show commands without applying")
    parser.add_argument('--clear', action='store_true', help="Clear existing descriptions instead of applying")
    parser.add_argument('--audit_csv', help="Path to save audit CSV log")
    args = parser.parse_args()

    logger = setup_logger("interface_descriptions", level=args.log_level)
    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Processing interface descriptions for {len(devices)} devices...")
    audit_log = []
    for device in devices:
        result = apply_interface_descriptions(device, logger, args.dry_run, args.clear, audit_log)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit CSV log saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Parser
# - Parse inventory file, log level, dry_run, clear flag, audit CSV path

#2: Load and validate devices

#3: Command Generation
# - If `--clear`, use `no description`, else apply description

#4: Per-Device Processing
# - Skip if no interface_descriptions
# - In dry-run, log the planned commands
# - Else send config via Netmiko

#5: Audit Logging
# - For each interface, log Device, Interface, Description, Status
# - Export to CSV if `--audit_csv` is provided

#6: Entry Point
# - Call main()

