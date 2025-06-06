import re
import csv
import os
import logging
import argparse
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

DEFAULT_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

DEVICE_LIST = [
    {"device_type": "cisco_ios", "ip": "192.168.1.1", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH},
    {"device_type": "cisco_ios", "ip": "192.168.1.2", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH}
]

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s - %(message)s')

def parse_version_output(output: str) -> Tuple[Optional[str], Optional[str]]:
    host = re.search(r"(\S+)\suptime", output)
    model = re.search(r"[Cc]isco\s+(\S+)\s+\(.+\)\s+processor", output)
    return host.group(1) if host else None, model.group(1) if model else None

def parse_ip_brief(output: str) -> Optional[str]:
    for line in output.splitlines():
        if "Interface" in line or "unassigned" in line:
            continue
        parts = line.split()
        if len(parts) >= 6 and parts[4].lower() == "up" and parts[5].lower() == "up":
            return parts[1]
    return None

def gather_device_summary(device: Dict) -> Dict[str, str]:
    try:
        logging.info(f"Connecting to {device['ip']}")
        with ConnectHandler(**device) as conn:
            version = conn.send_command("show version")
            ip_brief = conn.send_command("show ip interface brief")
            hostname, model = parse_version_output(version)
            ip = parse_ip_brief(ip_brief)
            return {
                "Hostname": hostname or "Unknown",
                "IP Address": ip or device["ip"],
                "Model": model or "Unknown"
            }
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        logging.warning(f"Connection failed to {device['ip']}: {e}")
        return {"Hostname": "Failed", "IP Address": device["ip"], "Model": "N/A"}

def generate_summary(devices: List[Dict], threads: int = 4) -> List[Dict[str, str]]:
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(gather_device_summary, dev) for dev in devices]
        return [f.result() for f in as_completed(futures)]

def write_summary_csv(data: List[Dict[str, str]], filename: str):
    try:
        with open(filename, mode="w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["Hostname", "IP Address", "Model"])
            writer.writeheader()
            writer.writerows(data)
        logging.info(f"Summary written to {filename}")
    except Exception as e:
        logging.error(f"Error writing to CSV: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Generate network topology summary.")
    parser.add_argument("--output", default="topology_summary.csv", help="CSV output filename")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for SSH sessions")
    return parser.parse_args()

def main():
    setup_logging()
    args = parse_args()
    results = generate_summary(DEVICE_LIST, threads=args.threads)
    write_summary_csv(results, filename=args.output)

if __name__ == "__main__":
    main()
