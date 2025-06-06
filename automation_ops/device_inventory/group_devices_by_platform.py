import re
import csv
import os
import logging
import argparse
from typing import List, Dict, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

DEFAULT_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

DEVICE_INVENTORY = [
    {"device_type": "cisco_ios", "ip": "192.168.1.1", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH},
    {"device_type": "cisco_nxos", "ip": "192.168.1.2", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH},
    {"device_type": "cisco_asa", "ip": "192.168.1.3", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH}
]

def configure_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s - %(message)s')

def classify_platform(output: str) -> str:
    if "NX-OS" in output:
        return "NX-OS"
    if "ASA" in output or "Adaptive Security Appliance" in output:
        return "ASA"
    if "Cisco IOS Software" in output:
        return "IOS"
    return "Unknown"

def extract_hostname(output: str, fallback: str) -> str:
    match = re.search(r"(\S+)\suptime", output)
    return match.group(1) if match else fallback

def fetch_device_info(device: Dict) -> Optional[Dict[str, str]]:
    try:
        logging.info(f"Connecting to {device['ip']}")
        with ConnectHandler(**device) as conn:
            output = conn.send_command("show version")
            platform = classify_platform(output)
            hostname = extract_hostname(output, fallback=device["ip"])
            return {"Platform": platform, "Hostname": hostname, "IP": device["ip"]}
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        logging.warning(f"Failed to connect to {device['ip']}: {e}")
        return None

def collect_platform_groups(devices: List[Dict], max_threads: int = 4) -> Dict[str, List[Dict[str, str]]]:
    groups = defaultdict(list)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(fetch_device_info, d) for d in devices]
        for future in as_completed(futures):
            result = future.result()
            if result:
                groups[result["Platform"]].append({"Hostname": result["Hostname"], "IP": result["IP"]})
    return groups

def export_to_csv(groups: Dict[str, List[Dict[str, str]]], filepath: str):
    try:
        with open(filepath, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "Hostname", "IP"])
            for platform, entries in groups.items():
                for entry in entries:
                    writer.writerow([platform, entry["Hostname"], entry["IP"]])
        logging.info(f"Platform grouping saved to {filepath}")
    except Exception as e:
        logging.error(f"Error writing CSV: {e}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Group network devices by platform")
    parser.add_argument("--output", default="device_platform_groups.csv", help="CSV output path")
    parser.add_argument("--threads", type=int, default=4, help="Number of concurrent threads")
    return parser.parse_args()

def main():
    configure_logging()
    args = parse_arguments()
    grouped = collect_platform_groups(DEVICE_INVENTORY, max_threads=args.threads)
    export_to_csv(grouped, filepath=args.output)

if __name__ == "__main__":
    main()
