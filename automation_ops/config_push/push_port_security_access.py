import argparse
import yaml
import re
import csv
from typing import Dict, List
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_security_template(template_file: str) -> List[str]:
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
        return data.get('port_security', [])


def load_interface_map(csv_path: str) -> Dict[str, List[str]]:
    mapping = {}
    with open(csv_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip = row['IP']
            interface = row['Interface']
            mapping.setdefault(ip, []).append(interface)
    return mapping


def apply_security_config(device: Dict[str, str], base_cmds: List[str], interface_map: Dict[str, List[str]], logger, dry_run: bool, strict: bool, audit_log: List[Dict[str, str]]) -> str:
    ip = device.get("host")
    hostname = device.get("hostname", ip)

    interfaces = interface_map.get(ip, [])
    if not interfaces:
        logger.warning(f"{ip}: No interfaces found in CSV mapping, skipping")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "SKIPPED", "Commands": 0})
        return f"{ip}: SKIPPED"

    config_cmds = []
    for intf in interfaces:
        config_cmds.append(f"interface {intf}")
        config_cmds.extend(base_cmds)

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Port security config to apply:")
        for cmd in config_cmds:
            logger.info(f"  {cmd}")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "DRY-RUN", "Commands": len(config_cmds)})
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
        if strict and 'Invalid input' in result:
            raise Exception("Command failed under strict mode")

        logger.info(f"{ip}: Port security config applied successfully.")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "SUCCESS", "Commands": len(config_cmds)})
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to apply port security config - {e}")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "FAILED", "Commands": len(config_cmds)})
        return f"{ip}: FAILED"


def export_audit_log(audit_data: List[Dict[str, str]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["IP", "Hostname", "Status", "Commands"])
        writer.writeheader()
        writer.writerows(audit_data)


def main():
    parser = argparse.ArgumentParser(description="Push port security access config to switch ports")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--template', required=True, help="YAML template file with 'port_security' key")
    parser.add_argument('--interfaces_csv', required=True, help="CSV with IP and Interface columns")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--strict', action='store_true', help="Fail entire device config if any command fails")
    parser.add_argument('--filter', help="Regex to filter devices by IP or hostname")
    parser.add_argument('--audit_csv', help="Path to save audit CSV log")
    args = parser.parse_args()

    logger = setup_logger("push_port_security", level=args.log_level)
    base_cmds = load_security_template(args.template)
    interface_map = load_interface_map(args.interfaces_csv)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    if args.filter:
        regex = re.compile(args.filter)
        devices = [d for d in devices if regex.search(d.get("host", "")) or regex.search(d.get("hostname", ""))]

    logger.info(f"Pushing port security config to {len(devices)} devices...")
    audit_log = []
    for device in devices:
        result = apply_security_config(device, base_cmds, interface_map, logger, args.dry_run, args.strict, audit_log)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit log saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Arguments
# - Inventory file, port_security template, interfaces CSV
# - --filter: hostname/IP regex
# - --dry_run, --strict, --audit_csv

#2: Load Templates
# - Load base port-security commands from YAML
# - Load per-device interface map from CSV

#3: Load & Filter Devices
# - Validate IPs
# - Apply regex if --filter set

#4: Per-Device Config
# - For each interface from CSV:
#     - enter interface mode
#     - apply port-security commands
# - If --dry_run: log commands
# - If --strict and any command fails: fail config
# - Record result in audit log (IP, hostname, status, command count)

#5: Export Audit CSV

#6: main()

