import argparse
import csv
import re
from typing import Dict, List
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def parse_interface_status(output: str, exclude_pattern: str) -> List[str]:
    issues = []
    for line in output.splitlines():
        if line.strip() == '' or 'Port' in line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            interface, status, protocol = parts[0], parts[1], parts[2]
            if exclude_pattern and re.search(exclude_pattern, interface):
                continue
            if status.lower() != 'up' or protocol.lower() != 'up':
                issues.append(f"{interface} is {status}/{protocol}")
    return issues


def audit_interface_status(device: Dict[str, str], logger, exclude_pattern: str) -> Dict[str, List[str]]:
    ip, output = connect_device_with_retries(
        device,
        commands=["show interfaces status"],
        retries=3,
        delay=2,
        debug=False
    )

    logger.info(f"Device {ip}: Checking interface status")

    if "Failed" in output or "Exception" in output:
        logger.error(f"Device {ip} connection failed: {output}")
        return {ip: [f"FAIL: {output}"]}

    issues = parse_interface_status(output, exclude_pattern)
    return {ip: issues if issues else ["All interfaces are up/up"]}


def export_issues_to_csv(results: List[Dict[str, List[str]]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Interface Issue"])
        for result in results:
            for ip, messages in result.items():
                for msg in messages:
                    if "is" in msg:
                        writer.writerow([ip, msg])


def main():
    parser = argparse.ArgumentParser(description="Interface Status Audit Tool")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--exclude', default="", help="Regex pattern to exclude interfaces (e.g. ^Vlan)")
    parser.add_argument('--csv', help="Path to export interface issues to CSV")
    args = parser.parse_args()

    logger = setup_logger("interface_audit", level=args.log_level)
    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Auditing interface status on {len(devices)} devices...")
    results = []
    for device in devices:
        result = audit_interface_status(device, logger, args.exclude)
        results.append(result)

    logger.info("\n--- INTERFACE STATUS SUMMARY ---")
    for r in results:
        for ip, messages in r.items():
            logger.info(f"{ip}:")
            for msg in messages:
                logger.info(f"  {msg}")

    if args.csv:
        export_issues_to_csv(results, args.csv)
        logger.info(f"Interface issues exported to CSV: {args.csv}")


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - Import standard and custom modules (Netmiko conn, logger, inventory)
# - Include regex and CSV support

#2: Parse Interface Output
# - For each line in `show interfaces status`:
#   - Skip header and blank lines
#   - Extract interface name, status, and protocol
#   - If name matches `exclude_pattern`, skip it
#   - If status/protocol not both 'up', record as an issue

#3: Audit Function per Device
# - Connect with retries
# - Run command and parse interface issues
# - Return per-device results

#4: Export Results to CSV
# - For each IP and issue, write to CSV
# - Only write if message includes actual interface status (not summary)

#5: Main Execution
# - Parse CLI args: inventory file, log level, regex exclude, CSV path
# - Load and validate device list
# - Audit each device and collect results
# - Log all findings
# - Export to CSV if path provided

#6: Entry Point
# - Run main()
