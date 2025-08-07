import argparse
from typing import Dict, List
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def generate_toggle_commands(interfaces: List[str], action: str) -> List[str]:
    if action == 'shutdown':
        return [f"interface {iface}\n shutdown" for iface in interfaces]
    elif action == 'no shutdown':
        return [f"interface {iface}\n no shutdown" for iface in interfaces]
    else:
        raise ValueError("Action must be 'shutdown' or 'no shutdown'")


def toggle_interfaces(device: Dict[str, str], interfaces: List[str], action: str, logger, dry_run: bool) -> str:
    ip = device.get('host')
    commands = generate_toggle_commands(interfaces, action)

    if dry_run:
        logger.info(f"[DRY-RUN] {ip}: Commands to apply:")
        for cmd in commands:
            logger.info(f"  {cmd.replace(chr(10), '; ')}")
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
        logger.info(f"{ip}: Successfully applied {action} to interfaces: {', '.join(interfaces)}")
        return f"{ip}: SUCCESS"
    except Exception as e:
        logger.error(f"{ip}: ERROR applying {action} - {e}")
        return f"{ip}: FAILED"


def main():
    parser = argparse.ArgumentParser(description="Bulk Interface Admin Toggle Tool")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--interfaces', nargs='+', help="Global interfaces to target (space-separated list)")
    parser.add_argument('--action', choices=['shutdown', 'no shutdown'], required=True, help="Action to apply")
    parser.add_argument('--dry_run', action='store_true', help="Print commands without applying them")
    args = parser.parse_args()

    logger = setup_logger("interface_toggle", level=args.log_level)
    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Applying '{args.action}' to interfaces on {len(devices)} devices...")
    for device in devices:
        device_interfaces = device.get("interfaces", args.interfaces or [])
        if not device_interfaces:
            logger.warning(f"{device.get('host')}: No interfaces specified, skipping.")
            continue
        result = toggle_interfaces(device, device_interfaces, args.action, logger, args.dry_run)
        logger.info(result)


if __name__ == '__main__':
    main()

#1: Parse CLI arguments
# - Accept inventory file, log level, action (shutdown/no shutdown)
# - Optionally accept global interface list
# - Add `--dry_run` flag

#2: Load and validate devices
# - Read from YAML and validate IPs

#3: Interface Command Generation
# - Build config commands from list of interfaces and chosen action

#4: Toggle Logic per Device
# - Use per-device `interfaces:` field if defined, else use global
# - If dry-run, print planned commands
# - Else, apply via Netmiko with retries

#5: Logging
# - Log results for each device: success, failure, or dry-run

#6: Entry Point
# - Call `main()`

