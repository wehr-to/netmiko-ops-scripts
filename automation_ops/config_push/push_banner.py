import argparse
import yaml
import re
from typing import Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def load_banner_template(template_file: str) -> str:
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
        return data.get('banner', '')


def apply_banner_config(device: Dict[str, str], banner: str, banner_type: str, logger, dry_run: bool) -> str:
    ip = device.get("host")
    banner_cmd = f"banner {banner_type} #\n{banner}\n#"

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Banner to apply:")
        logger.info(banner_cmd)
        return f"{ip}: DRY-RUN"

    try:
        ip, result = connect_device_with_retries(
            device,
            config_commands=[banner_cmd],
            commands=[],
            retries=3,
            delay=2,
            debug=False
        )
        logger.info(f"{ip}: Banner applied successfully.")
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: Failed to apply banner - {e}")
        return f"{ip}: FAILED"


def main():
    parser = argparse.ArgumentParser(description="Push banner config to devices")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--template', required=True, help="YAML template file with 'banner' key")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--dry_run', action='store_true', help="Preview commands without applying")
    parser.add_argument('--type', choices=['motd', 'login', 'exec'], default='motd', help="Banner type to apply")
    parser.add_argument('--filter', help="Regex filter for hostnames or IPs")
    args = parser.parse_args()

    logger = setup_logger("push_banner", level=args.log_level)
    banner_text = load_banner_template(args.template)

    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    if args.filter:
        pattern = re.compile(args.filter)
        devices = [d for d in devices if pattern.search(d.get("host", "")) or pattern.search(d.get("hostname", ""))]

    logger.info(f"Pushing {args.type} banner to {len(devices)} devices...")
    for device in devices:
        result = apply_banner_config(device, banner_text, args.type, logger, args.dry_run)
        logger.info(result)


if __name__ == '__main__':
    main()

#1: CLI Arguments
# - --file: YAML inventory
# - --template: YAML with 'banner' key
# - --type: banner type (motd, login, exec)
# - --dry_run
# - --filter: regex match hostname/IP
# - --log_level

#2: Load Template
# - Parse banner string

#3: Load Devices
# - Validate IPs
# - Filter by regex if --filter used

#4: Apply Banner
# - Construct: banner <type> #<text>#
# - If dry-run, log only
# - Else push via Netmiko and log result

#5: Call main()

