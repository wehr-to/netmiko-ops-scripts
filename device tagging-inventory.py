#1 Create device inventory file from show version

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

#2 Generate topology summary (hostname, IP, model)

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

#3 Group devices by platform / REFACTOR TO THE END

import csv
from collections import defaultdict
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
import re

# Example device list
devices = [
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.1",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
    {
        "device_type": "cisco_nxos",
        "ip": "192.168.1.2",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
    {
        "device_type": "cisco_asa",
        "ip": "192.168.1.3",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
]

def determine_platform(show_version_output):
    """Returns platform type based on version string."""
    if "NX-OS" in show_version_output:
        return "NX-OS"
    elif "ASA" in show_version_output or "Adaptive Security Appliance" in show_version_output:
        return "ASA"
    elif "Cisco IOS Software" in show_version_output:
        return "IOS"
    else:
        return "Unknown"

def main():
    platform_groups = defaultdict(list)

    for device in devices:
        try:
            print(f"[+] Connecting to {device['ip']}...")
            connection = ConnectHandler(**device)
            output = connection.send_command("show version")
            platform = determine_platform(output)
            hostname_match = re.search(r"(\S+)\suptime", output)
            hostname = hostname_match.group(1) if hostname_match else device["ip"]

            platform_groups[platform].append({
                "Hostname": hostname,
                "IP": device["ip"]
            })

            connection.disconnect()

        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            print(f"[-] Failed to connect to {device['ip']}: {e}")

    # Output CSV for visibility
    with open("device_platform_groups.csv", mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Platform", "Hostname", "IP"])
        for platform, devices in platform_groups.items():
            for entry in devices:
                writer.writerow([platform, entry["Hostname"], entry["IP"]])

    print("[+] Devices grouped by platform. Results saved to 'device_platform_groups.csv'")

if __name__ == "__main__":
    main()

#4 Parse serial numbers for asset tracking

import csv
import re
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Example device list
devices = [
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.1",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.2",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
]

def extract_serial(show_version_output):
    """Extracts the serial number from 'show version' output."""
    # Newer Cisco devices
    match = re.search(r"System serial number\s*:\s*(\S+)", show_version_output)
    if match:
        return match.group(1)
    
    # Older IOS format
    match = re.search(r"Processor board ID\s+(\S+)", show_version_output)
    if match:
        return match.group(1)

    return "Unknown"

def extract_hostname(output):
    match = re.search(r"(\S+)\suptime", output)
    return match.group(1) if match else "Unknown"

def main():
    results = []

    for device in devices:
        try:
            print(f"[+] Connecting to {device['ip']}...")
            connection = ConnectHandler(**device)
            output = connection.send_command("show version")

            hostname = extract_hostname(output)
            serial = extract_serial(output)

            results.append({
                "Hostname": hostname,
                "IP": device["ip"],
                "Serial Number": serial
            })

            print(f"[+] {hostname} - Serial: {serial}")
            connection.disconnect()

        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            print(f"[-] Connection failed to {device['ip']}: {e}")

    # Output to CSV
    with open("device_serials.csv", mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Hostname", "IP", "Serial Number"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print("[+] Serial number inventory saved to 'device_serials.csv'")

if __name__ == "__main__":
    main()

#5 Tag interfaces based on connected device names

import csv
import re
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Device list to tag interfaces on
devices = [
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.1",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.2",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
]

def parse_cdp_neighbors(output):
    """
    Parses 'show cdp neighbors' output.
    Returns list of tuples: (local_interface, remote_device, remote_interface)
    """
    neighbors = []
    lines = output.splitlines()
    for line in lines:
        if re.search(r"\bEth|Gig|Fa|Ten|Se\b", line) and "Device" not in line:
            parts = line.split()
            if len(parts) >= 5:
                remote_device = parts[0]
                local_intf = parts[1] + parts[2]
                remote_intf = parts[-2] + parts[-1]
                neighbors.append((local_intf, remote_device, remote_intf))
    return neighbors

def tag_interfaces(device):
    try:
        print(f"[+] Connecting to {device['ip']}...")
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")

        output = connection.send_command("show cdp neighbors")
        neighbor_data = parse_cdp_neighbors(output)

        if not neighbor_data:
            print(f"[!] No CDP neighbors found on {hostname}")
            return

        config_commands = []
        for local_intf, remote_host, remote_intf in neighbor_data:
            desc = f"Connected to {remote_host} {remote_intf}"
            config_commands.append(f"interface {local_intf}")
            config_commands.append(f"description {desc}")

        connection.send_config_set(config_commands)
        connection.save_config()
        print(f"[+] Tagged {len(neighbor_data)} interfaces on {hostname}")
        connection.disconnect()

        return [(hostname, local, remote, remote_intf) for local, remote, remote_intf in neighbor_data]

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")
        return []

def main():
    all_tags = []

    for device in devices:
        tags = tag_interfaces(device)
        if tags:
            all_tags.extend(tags)

    # Save to CSV log
    with open("interface_tags.csv", mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Device", "Local Interface", "Connected To", "Remote Interface"])
        for row in all_tags:
            writer.writerow(row)

    print("[+] Interface tags logged in 'interface_tags.csv'")

if __name__ == "__main__":
    main()


#6 Export interface MAC tables for endpoint mapping

import csv
import re
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Example device list (replace with YAML or shared loader later)
devices = [
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.10",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
    {
        "device_type": "cisco_ios",
        "ip": "192.168.1.11",
        "username": "admin",
        "use_keys": True,
        "key_file": "/home/youruser/.ssh/id_rsa"
    },
]

def parse_mac_table(output):
    """
    Parses 'show mac address-table' output into structured data.
    Returns a list of dictionaries with VLAN, MAC, Type, and Interface.
    """
    entries = []
    lines = output.splitlines()

    for line in lines:
        # Example line format: "  10    aabb.ccdd.eeff    DYNAMIC     Gi1/0/1"
        match = re.match(r"^\s*(\d+)\s+([0-9a-f.]+)\s+(\w+)\s+(\S+)", line, re.IGNORECASE)
        if match:
            vlan, mac, mac_type, interface = match.groups()
            entries.append({
                "VLAN": vlan,
                "MAC Address": mac,
                "Type": mac_type.upper(),
                "Interface": interface
            })

    return entries

def export_mac_table(device):
    try:
        print(f"[+] Connecting to {device['ip']}...")
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")

        output = connection.send_command("show mac address-table")
        mac_entries = parse_mac_table(output)

        for entry in mac_entries:
            entry["Hostname"] = hostname
            entry["IP"] = device["ip"]

        connection.disconnect()
        print(f"[+] Retrieved {len(mac_entries)} MAC entries from {hostname}")
        return mac_entries

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Connection failed to {device['ip']}: {e}")
        return []

def main():
    all_entries = []

    for device in devices:
        mac_table = export_mac_table(device)
        all_entries.extend(mac_table)

    # Output to CSV
    with open("mac_address_table.csv", mode="w", newline="") as file:
        fieldnames = ["Hostname", "IP", "VLAN", "MAC Address", "Type", "Interface"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_entries:
            writer.writerow(row)

    print("[+] MAC address table exported to 'mac_address_table.csv'")

if __name__ == "__main__":
    main()



