# connects to routers, runs show ip bgp summary, parses neighbor states, and exports them to CSV for auditing.

import argparse
import csv
import re
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def parse_bgp_neighbors(output: str) -> List[Dict[str, str]]:
    neighbors = []
    for line in output.splitlines():
        match = re.search(r"BGP neighbor is (\S+), remote AS (\d+), (\S+)", line)
        if match:
            state_match = re.search(r"BGP state = (\S+), up for (.*)", output)
            neighbors.append({
                "Neighbor IP": match.group(1),
                "Remote AS": match.group(2),
                "Link": match.group(3),
                "State": state_match.group(1) if state_match else "UNKNOWN",
                "Up Time": state_match.group(2) if state_match else "N/A"
            })
    return neighbors


def check_bgp(device: Dict[str, str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ip, output = connect_device_with_retries(
            device,
            commands=["show ip bgp summary"],
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        parsed = []
        for line in output.splitlines():
            fields = line.split()
            if re.match(r"\d+\.\d+\.\d+\.\d+", line):
                neighbor_ip = fields[0]
                state = fields[-1] if fields[-1].isalpha() else "Established"
                parsed.append({
                    "IP": ip,
                    "Hostname": hostname,
                    "Neighbor": neighbor_ip,
                    "State": state
                })
        logger.info(f"{ip}: Checked {len(parsed)} BGP neighbors")
        return parsed
    except Exception as e:
        logger.error(f"{ip}: BGP check failed - {e}")
        return [{"IP": ip, "Hostname": hostname, "Neighbor": "ERROR", "State": str(e)}]


def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = sorted(data[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(description="Check BGP neighbor states on routers")
    parser.add_argument('--inventory', required=True, help="YAML inventory file")
    parser.add_argument('--output', required=True, help="CSV output file")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("bgp_check", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    results = []
    for device in devices:
        results.extend(check_bgp(device, logger))

    export_to_csv(results, args.output)
    logger.info(f"BGP neighbor state audit exported to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML list
# --output: CSV export
# --log_level

#2: Load & Validate Devices

#3: For Each Device
# - Run 'show ip bgp summary'
# - Extract neighbor IP and state
# - Tag with device IP + hostname

#4: Export to CSV

#5: main()

