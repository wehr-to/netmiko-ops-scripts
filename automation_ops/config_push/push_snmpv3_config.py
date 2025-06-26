import argparse
import yaml
import re
import csv
from typing import Dict, List
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_snmpv3_template(template_file: str) -> List[str]:
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
        return data.get('snmpv3', [])


def build_device_snmpv3_config(device: Dict[str, str], base_cmds: List[str]) -> List[str]:
    username = device.get("snmp_user", "netops")
    auth = device.get("snmp_auth", "md5")
    priv = device.get("snmp_priv", "aes")
    password = device.get("snmp_password", "NetOps123")

    config = []
    for cmd in base_cmds:
        cmd = cmd.replace("<user>", username)
        cmd = cmd.replace("<auth>", auth)
        cmd = cmd.replace("<priv>", priv)
        cmd = cmd.replace("<password>", password)
        config.append(cmd)
    return config


def apply_snmpv3_config(device: Dict[str, str], base_cmds: List[str], logger, dry_run: bool, audit_log: List[Dict[str, str]], remove_existing: bool) -> str:
    ip = device.get("host")
    hostname = device.get("hostname", ip)

    config_cmds = []
    if remove_existing:
        config_cmds.extend([
            "no snmp-server group netops v3 priv",
            "no snmp-server user netops netops v3"
        ])
    config_cmds.extend(build_device_snmpv3_config(device, base_cmds))

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: SNMPv3 config commands to apply:")
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
        logger.info(f"{ip}: SNMPv3 config applied successfully.")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "SUCCESS", "Commands": len(config_cmds)})
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to apply SNMPv3 config - {e}")
        audit_log.append({"IP": ip, "Hostname": hostname, "Status": "FAILED", "Commands": len(config_cmds)})
        return f"{ip}: FAILED"


def export_audit_log(audit_data: List[Dict[str, str]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["IP", "Hostname", "Status", "Commands"])
        writer.writeheader()
        writer.writerows(audit_data)


def main():
    parser = argparse.ArgumentParser(description="Push SNMPv3 config to network devices")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--template', required=True, help="YAML template file with 'snmpv3' key")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--remove_existing', action='store_true', help="Remove old SNMP users/groups before applying new config")
    parser.add_argument('--filter', help="Regex to filter devices by IP or hostname")
    parser.add_argument('--audit_csv', help="Path to save audit CSV log")
    args = parser.parse_args()

    logger = setup_logger("push_snmpv3", level=args.log_level)
    base_cmds = load_snmpv3_template(args.template)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    if args.filter:
        regex = re.compile(args.filter)
        devices = [d for d in devices if regex.search(d.get("host", "")) or regex.search(d.get("hostname", ""))]

    logger.info(f"Pushing SNMPv3 config to {len(devices)} devices...")
    audit_log = []
    for device in devices:
        result = apply_snmpv3_config(device, base_cmds, logger, args.dry_run, audit_log, args.remove_existing)
        logger.info(result)

    if args.audit_csv:
        export_audit_log(audit_log, args.audit_csv)
        logger.info(f"Audit log saved to {args.audit_csv}")


if __name__ == '__main__':
    main()

#1: CLI Flags
# - --file, --template, --log_level, --dry_run
# - --remove_existing: delete existing SNMPv3 config
# - --filter: IP/hostname regex
# - --audit_csv: path for result export

#2: Load Templates
# - SNMPv3 command list with placeholders

#3: Load & Filter Devices
# - Validate IPs
# - Filter by regex if needed

#4: For Each Device
# - If --remove_existing, prepend cleanup commands
# - Fill in device-specific SNMP credentials in template
# - If --dry_run: print commands only
# - Else: apply via Netmiko
# - Log result with IP, hostname, status, command count

#5: Export CSV if requested

#6: main()
