# connects to devices, runs CPU and memory commands, parses usage data, and exports a CSV for tracking.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_cpu_memory(output: str) -> Dict[str, str]:
    cpu = ""
    mem_used = ""
    mem_total = ""
    for line in output.splitlines():
        if "CPU utilization" in line:
            match = re.search(r"five seconds: (\d+)%", line)
            if match:
                cpu = match.group(1)
        if "Processor Pool Total" in line:
            parts = line.split()
            if len(parts) >= 5:
                mem_total = parts[3]
                mem_used = parts[4]
    return {
        "CPU (%)": cpu,
        "Memory Used": mem_used,
        "Memory Total": mem_total
    }


def collect_cpu_memory(device: Dict[str, str], logger) -> Dict[str, str]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show processes cpu | include CPU", "show processes memory | include Processor"],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = parse_cpu_memory(output)
        parsed["IP"] = ip
        parsed["Hostname"] = hostname
        logger.info(f"{ip}: CPU/Memory info collected")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: Error retrieving CPU/Memory - {e}")
        return {"IP": ip, "Hostname": hostname, "CPU (%)": "ERROR", "Memory Used": "", "Memory Total": ""}


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Monitor CPU and memory usage across devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("cpu_mem_monitor", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.append(collect_cpu_memory(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"CPU/Memory data saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML inventory file
# --output: CSV export
# --log_level

#2: Load & Validate Devices

#3: For Each Device
# - Run:
#   - show processes cpu | include CPU
#   - show processes memory | include Processor
# - Extract:
#   - CPU (%), Memory Used, Memory Total
# - Add IP + Hostname

#4: Export to CSV:
# IP, Hostname, CPU (%), Memory Used, Memory Total

#5: main()
