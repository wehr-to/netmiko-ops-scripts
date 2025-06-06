import csv
import re
import os
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

DEFAULT_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

DEVICES = [
    {"device_type": "cisco_ios", "ip": "192.168.1.1", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH},
    {"device_type": "cisco_ios", "ip": "192.168.1.2", "username": "admin", "use_keys": True, "key_file": DEFAULT_KEY_PATH}
]

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def connect_and_collect(device: dict) -> dict:
    try:
        logging.info(f"Connecting to {device['ip']}...")
        with ConnectHandler(**device) as conn:
            output = conn.send_command("show version")
            parsed = parse_show_version(output)
            parsed["IP"] = device["ip"]
            logging.info(f"Collected data from {parsed['Hostname']}")
            return parsed
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        logging.warning(f"Connection failed for {device['ip']}: {e}")
        return {"Hostname": "Failed", "IP": device["ip"], "Model": "N/A", "Version": "N/A", "Serial Number": "N/A"}
    except Exception as e:
        logging.error(f"Unexpected error with {device['ip']}: {e}")
        return {"Hostname": "Error", "IP": device["ip"], "Model": "N/A", "Version": "N/A", "Serial Number": "N/A"}

def parse_show_version(output: str) -> dict:
    hostname = re.search(r"(\S+)\suptime", output)
    model = re.search(r"[Cc]isco\s+(\S+)\s+\(.+\)\s+processor", output)
    version = re.search(r"Cisco IOS Software.*, Version\s+([\S]+)", output)
    serial = re.search(r"System serial number\s+:\s+(\S+)", output) or \
             re.search(r"Processor board ID\s+(\S+)", output)

    return {
        "Hostname": hostname.group(1) if hostname else "Unknown",
        "Model": model.group(1) if model else "Unknown",
        "Version": version.group(1) if version else "Unknown",
        "Serial Number": serial.group(1) if serial else "Unknown"
    }

def collect_inventory(devices: list, max_workers: int = 5) -> list:
    inventory = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_device = {executor.submit(connect_and_collect, device): device for device in devices}
        for future in as_completed(future_to_device):
            result = future.result()
            inventory.append(result)
    return inventory

def write_inventory_to_csv(data: list, filename: str):
    fieldnames = ["Hostname", "IP", "Model", "Version", "Serial Number"]
    try:
        with open(filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        logging.info(f"Inventory written to {filename}")
    except Exception as e:
        logging.error(f"Failed to write CSV: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Collect Cisco device inventory and save to CSV.")
    parser.add_argument("--output", default="device_inventory.csv", help="CSV filename to save inventory")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel threads")
    return parser.parse_args()

def main():
    setup_logger()
    args = parse_args()
    inventory = collect_inventory(DEVICES, max_workers=args.threads)
    write_inventory_to_csv(inventory, filename=args.output)

if __name__ == "__main__":
    main()
