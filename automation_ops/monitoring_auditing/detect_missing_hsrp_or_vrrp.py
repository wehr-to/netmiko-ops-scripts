# Detect devices missing HSRP or VRRP configs
# checks each device for the presence of HSRP or VRRP using show standby and show vrrp, and reports missing redundancy configurations.

import argparse
import csv
import re
from typing import List, Dict
from pathlib import Path
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def load_interfaces_csv(path: str) -> Dict[str, List[str]]:
    result = {}
    with open(path, newline='') as f:
        for row in csv.DictReader(f):
            ip = row['IP']
            intf = row['Interface']
            result.setdefault(ip, []).append(intf)
    return result


def check_hsrp_vrrp(output: str, protocol: str) -> List[str]:
    found = []
    if protocol in ('all', 'hsrp'):
        if re.findall(r"Standby +\d+", output, re.IGNORECASE):
            found.append("HSRP")
    if protocol in ('all', 'vrrp'):
        if re.findall(r"VRRP +\d+", output, re.IGNORECASE):
            found.append("VRRP")
    return found


def audit_redundancy_protocols(device: Dict[str, str], logger, protocol: str, intf_map: Dict[str, List[str]]) -> Dict[str, str]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show standby", "show vrrp"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        if ip in intf_map:
            lines = [line for line in output.splitlines() if any(intf in line for intf in intf_map[ip])]
            output = "\n".join(lines)

        protocols = check_hsrp_vrrp(output, protocol)
        logger.info(f"{ip}: Protocols detected: {protocols if protocols else 'None'}")
        return {
            "IP": ip,
            "Hostname": hostname,
            "HSRP": "YES" if "HSRP" in protocols else "NO",
            "VRRP": "YES" if "VRRP" in protocols else "NO",
            "Status": "OK" if protocols else "MISSING"
        }
    except Exception as e:
        logger.error(f"{ip}: Error checking redundancy protocols - {e}")
        return {
            "IP": ip,
            "Hostname": hostname,
            "HSRP": "ERROR",
            "VRRP": "ERROR",
            "Status": f"FAILED: {e}"
        }


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    fields = ["IP", "Hostname", "HSRP", "VRRP", "Status"]
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Detect missing HSRP or VRRP on routers/switches")
    parser.add_argument('--inventory', required=True, help="Path to YAML inventory")
    parser.add_argument('--output', required=True, help="Path to output CSV")
    parser.add_argument('--protocol', choices=['all', 'hsrp', 'vrrp'], default='all', help="Protocol to audit")
    parser.add_argument('--interfaces_csv', help="CSV file with interfaces to audit per device")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("redundancy_audit", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    interface_map = load_interfaces_csv(args.interfaces_csv) if args.interfaces_csv else {}

    results = []
    for device in devices:
        result = audit_redundancy_protocols(device, logger, args.protocol, interface_map)
        results.append(result)

    export_to_csv(results, args.output)
    logger.info(f"Redundancy protocol audit saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML device file
# --output: CSV export
# --protocol: hsrp | vrrp | all
# --interfaces_csv: optional list of interfaces per device
# --log_level

#2: Load Inventory & Validate IPs

#3: Load --interfaces_csv into a dict[ip] = list[intfs]

#4: For Each Device
# - Run show standby and show vrrp
# - Optionally limit output to listed interfaces
# - Parse HSRP or VRRP groups depending on --protocol
# - Tag YES/NO/ERROR for each

#5: Write results to CSV

