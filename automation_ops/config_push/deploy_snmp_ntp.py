import argparse
import yaml
from typing import Dict, List
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def load_snmp_ntp_template(template_file: str, snmp_only: bool, ntp_only: bool) -> List[str]:
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
        cmds = []
        if snmp_only:
            cmds = data.get('snmp', [])
        elif ntp_only:
            cmds = data.get('ntp', [])
        else:
            cmds = data.get('snmp', []) + data.get('ntp', [])
        return cmds


def backup_running_config(device: Dict[str, str], logger) -> str:
    try:
        ip, output = connect_device_with_retries(device, commands="show running-config")
        filename = f"backup_{ip.replace('.', '_')}.cfg"
        with open(filename, 'w') as f:
            f.write(output)
        logger.info(f"{ip}: Backup saved to {filename}")
        return filename
    except Exception as e:
        logger.error(f"{device.get('host')}: Backup failed - {e}")
        return "BACKUP_FAILED"


def apply_snmp_ntp_config(device: Dict[str, str], config_cmds: List[str], logger, dry_run: bool, backup: bool) -> str:
    ip = device.get("host")

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: SNMP/NTP config commands to apply:")
        for cmd in config_cmds:
            logger.info(f"  {cmd}")
        return f"{ip}: DRY-RUN"

    if backup:
        backup_running_config(device, logger)

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=config_cmds,
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: SNMP/NTP configuration applied successfully.")
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to apply SNMP/NTP config - {e}")
        return f"{ip}: FAILED"


def main():
    parser = argparse.ArgumentParser(description="Deploy SNMP and NTP settings from YAML template")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--template', required=True, help="YAML template with 'snmp' and 'ntp' config")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--snmp_only', action='store_true', help="Apply only SNMP config")
    parser.add_argument('--ntp_only', action='store_true', help="Apply only NTP config")
    parser.add_argument('--backup', action='store_true', help="Backup running-config before applying changes")
    args = parser.parse_args()

    logger = setup_logger("snmp_ntp", level=args.log_level)
    config_cmds = load_snmp_ntp_template(args.template, args.snmp_only, args.ntp_only)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Deploying SNMP/NTP config to {len(devices)} devices...")
    for device in devices:
        result = apply_snmp_ntp_config(device, config_cmds, logger, args.dry_run, args.backup)
        logger.info(result)


if __name__ == '__main__':
    main()

#1: CLI Input
# - Parse: --file, --template, --dry_run, --log_level
# - Flags: --snmp_only, --ntp_only, --backup

#2: Load Config Template
# - Load YAML with 'snmp' and 'ntp' keys
# - Use flags to include/exclude relevant sections

#3: Load Device Inventory
# - Parse YAML
# - Validate IPs

#4: Deploy Loop
# For each device:
#  - If dry_run:
#    - Log commands and skip connection
#  - If backup:
#    - Save `show running-config` to local file
#  - Push config commands using Netmiko
#  - Log SUCCESS / FAILED per device

#5: Call main()

