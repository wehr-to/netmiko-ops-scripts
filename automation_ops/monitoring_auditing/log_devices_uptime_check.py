# connects to devices, extracts uptime info from show version, and logs results to a CSV.

import argparse
import csv
import re
from typing import List, Dict
from datetime import timedelta
from utils.logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def extract_uptime(output: str) -> str:
    for line in output.splitlines():
        if " uptime is " in line:
            return line.strip()
    return "Not found"


def parse_uptime_to_hours(uptime_str: str) -> float:
    # Example: "hostname uptime is 2 weeks, 5 days, 3 hours, 12 minutes"
    total_hours = 0
    time_units = {
        'week': 168,
        'day': 24,
        'hour': 1,
        'minute': 1/60
    }
    for unit, multiplier in time_units.items():
        match = re.search(rf"(\d+) {unit}s?", uptime_str)
        if match:
            total_hours += int(match.group(1)) * multiplier
    return round(total_hours, 2)


def check_device_uptime(device: Dict[str, str], logger, min_uptime: float) -> Dict[str, str]:
    ip = device['host']
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show version"],
            retries=2,
            delay=2,
            debug=False
        )
        uptime_line = extract_uptime(output)
        uptime_hours = parse_uptime_to_hours(uptime_line)
        compliance = "YES" if uptime_hours >= min_uptime else "NO"
        hostname = device.get('hostname', ip)
        logger.info(f"{ip}: Uptime {uptime_hours} hours")
        return {
            "IP": ip,
            "Hostname": hostname,
            "Uptime": uptime_line,
            "Hours": uptime_hours,
            "Compliant": compliance
        }
    except Exception as e:
        logger.error(f"{ip}: Failed to retrieve uptime - {e}")
        return {
            "IP": ip,
            "Hostname": device.get('hostname', ip),
            "Uptime": f"ERROR: {e}",
            "Hours": 0,
            "Compliant": "ERROR"
        }


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = ["IP", "Hostname", "Uptime", "Hours", "Compliant"]
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Check uptime of all devices and log to CSV")
    parser.add_argument('--inventory', required=True, help="Path to YAML inventory file")
    parser.add_argument('--output', required=True, help="Path to CSV output file")
    parser.add_argument('--min_uptime', type=float, default=0, help="Minimum uptime in hours to be considered compliant")
    parser.add_argument('--sort_by_uptime', action='store_true', help="Sort CSV output by uptime hours descending")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    args = parser.parse_args()

    logger = setup_logger("uptime_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.append(check_device_uptime(device, logger, args.min_uptime))

    if args.sort_by_uptime:
        results.sort(key=lambda x: x.get("Hours", 0), reverse=True)

    export_to_csv(results, args.output)
    logger.info(f"Uptime log written to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML file
# --output: CSV path
# --min_uptime: threshold in hours (default 0)
# --sort_by_uptime: sort descending by hours
# --log_level

#2: Load & Validate Devices

#3: For Each Device
# - Run 'show version'
# - Extract uptime line
# - Parse uptime to total hours
# - Mark compliant if uptime >= min_uptime

#4: Sort results (if flag)

#5: Export to CSV with:
# IP, Hostname, Uptime (raw), Hours, Compliant
