import argparse
from typing import List, Dict, Tuple
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
import ipaddress
import csv
import json
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries


def parse_arp_output(output: str) -> List[Tuple[str, str]]:
    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and ip_is_valid(parts[0]):
            entries.append((parts[0], parts[1]))
    return entries


def parse_route_output(output: str) -> List[str]:
    routes = []
    for line in output.splitlines():
        parts = line.split()
        if parts and ip_net_is_valid(parts[0]):
            routes.append(parts[0])
    return routes


def ip_is_valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_net_is_valid(net: str) -> bool:
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except ValueError:
        return False


def audit_device(device: Dict[str, str], logger, include_arp: bool, include_route: bool) -> Dict[str, Dict[str, List[str]]]:
    ip, output = connect_device_with_retries(
        device,
        commands=["show ip arp", "show ip route"],
        retries=3,
        delay=2,
        debug=False
    )

    logger.info(f"Device {ip}: running ARP and Routing audit")

    if "Failed" in output or "Exception" in output:
        logger.error(f"Device {ip} connection failed: {output}")
        return {ip: {"error": [output]}}

    outputs = output.split("\n")
    arp_lines = []
    route_lines = []
    arp_found = False

    for line in outputs:
        if "Protocol" in line and "Address" in line:
            arp_found = True
            continue
        if arp_found and line.strip() == "":
            arp_found = False
        if arp_found:
            arp_lines.append(line)
        else:
            route_lines.append(line)

    result = {}
    if include_arp:
        arp_entries = parse_arp_output("\n".join(arp_lines))
        logger.info(f"Device {ip}: Found {len(arp_entries)} ARP entries")
        result["arp"] = arp_entries

    if include_route:
        route_entries = parse_route_output("\n".join(route_lines))
        logger.info(f"Device {ip}: Found {len(route_entries)} routes")
        result["routes"] = route_entries

    return {ip: result}


def export_results_to_csv(results: List[Dict[str, Dict[str, List[str]]]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Type", "Data"])
        for result in results:
            for ip, data in result.items():
                for section, values in data.items():
                    if section == "error":
                        writer.writerow([ip, "error", values[0]])
                    else:
                        for val in values:
                            writer.writerow([ip, section, val])


def export_results_to_json(results: List[Dict[str, Dict[str, List[str]]]], json_path: str):
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="ARP & Routing Audit Tool")
    parser.add_argument('--file', required=True, help="Inventory file path (YAML format)")
    parser.add_argument('--log_level', default="INFO", help="Log level (e.g., DEBUG, INFO, ERROR)")
    parser.add_argument('--include_arp', action='store_true', help="Include ARP audit")
    parser.add_argument('--include_route', action='store_true', help="Include routing audit")
    parser.add_argument('--csv', help="Export results to CSV file")
    parser.add_argument('--json', help="Export results to JSON file")
    args = parser.parse_args()

    from parsers.inventory_parser import load_yaml_inventory, validate_ip
    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger = setup_logger("arp_audit", level=args.log_level)

    logger.info(f"Auditing {len(devices)} devices...")
    results = []
    for device in devices:
        result = audit_device(device, logger, args.include_arp, args.include_route)
        results.append(result)

    logger.info("\n--- AUDIT SUMMARY ---")
    for result in results:
        for ip, sections in result.items():
            logger.info(f"{ip}:")
            for sec, lines in sections.items():
                for line in lines:
                    logger.info(f"  [{sec.upper()}] {line}")

    if args.csv:
        export_results_to_csv(results, args.csv)
        logger.info(f"Results exported to CSV: {args.csv}")

    if args.json:
        export_results_to_json(results, args.json)
        logger.info(f"Results exported to JSON: {args.json}")


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - Import standard, Netmiko, IP validation, logging, JSON, CSV modules
# - Import custom logger and connection modules

#2: Define Parsers
# - parse_arp_output(): Extracts (IP, MAC) pairs from ARP command output
# - parse_route_output(): Extracts route destinations from routing table

#3: Device Audit Function
# - connect to device using retry logic
# - run both ARP and routing commands
# - split raw output into ARP and route blocks
# - conditionally include ARP and/or routing entries based on CLI flags
# - return parsed data in structured dict format

#4: Output Export
# - export_results_to_csv(): Write audit results to a CSV
# - export_results_to_json(): Dump audit results to a JSON file

#5: Main Function
# - Parse CLI args: inventory file, log level, include_arp, include_route, csv/json output
# - Load inventory (YAML), validate IPs
# - For each device, run audit_device() and collect results
# - Log summary output
# - If export paths provided, save results to CSV and/or JSON

#6: Run Main
# - main() entry point for CLI usage
