#1 Create device inventory file from show version

import csv
import re
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

DEVICES = [
    {"device_type": "cisco_ios", "ip": "192.168.1.1", "username": "admin", "use_keys": True, "key_file": "/home/youruser/.ssh/id_rsa"},
    {"device_type": "cisco_ios", "ip": "192.168.1.2", "username": "admin", "use_keys": True, "key_file": "/home/youruser/.ssh/id_rsa"}
]

def connect_device(device):
    try:
        print(f"[+] Connecting to {device['ip']}...")
        connection = ConnectHandler(**device)
        return connection
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[!] Connection failed for {device['ip']}: {e}")
        return None

def parse_show_version(output):
    """Parses show version output for hostname, model, version, and serial."""
    hostname = re.search(r"(\S+)\suptime", output)
    model = re.search(r"[Cc]isco\s+(\S+)\s+\(.+\)\s+processor", output)
    version = re.search(r"Cisco IOS Software.*, Version\s+([\S]+)", output)
    serial = re.search(r"System serial number\s+:\s+(\S+)", output) or re.search(r"Processor board ID\s+(\S+)", output)

    return {
        "Hostname": hostname.group(1) if hostname else "Unknown",
        "Model": model.group(1) if model else "Unknown",
        "Version": version.group(1) if version else "Unknown",
        "Serial Number": serial.group(1) if serial else "Unknown"
    }

def collect_inventory(devices):
    inventory = []

    for device in devices:
        conn = connect_device(device)
        if not conn:
            continue

        output = conn.send_command("show version")
        parsed = parse_show_version(output)
        parsed["IP"] = device["ip"]
        inventory.append(parsed)

        conn.disconnect()
        print(f"[+] Collected data from {parsed['Hostname']}")

    return inventory

def write_inventory_to_csv(data, filename="device_inventory.csv"):
    fieldnames = ["Hostname", "IP", "Model", "Version", "Serial Number"]
    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] Inventory written to {filename}")

# Single entrypoint at the bottom — clean and standard
def main():
    inventory = collect_inventory(DEVICES)
    write_inventory_to_csv(inventory)

main()


#2 Generate topology summary (hostname, IP, model)

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException
import re

# Device list (can later be imported from a CSV/YAML)
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

def parse_show_version(output):
    """Extracts hostname and model from 'show version' output."""
    hostname = None
    model = None

    # Hostname from uptime line
    hostname_match = re.search(r"(\S+)\suptime", output)
    if hostname_match:
        hostname = hostname_match.group(1)

    # Model from processor line
    model_match = re.search(r"[Cc]isco\s+(\S+)\s+\(.+\)\s+processor", output)
    if model_match:
        model = model_match.group(1)

    return hostname, model

def get_management_ip(output):
    """Extracts the first up/up interface IP from 'show ip int brief'."""
    lines = output.splitlines()
    for line in lines:
        if "Interface" in line or "unassigned" in line:
            continue
        parts = line.split()
        if len(parts) >= 6 and parts[4].lower() == "up" and parts[5].lower() == "up":
            return parts[1]  # IP address
    return None

def main():
    summary_data = []

    for device in devices:
        try:
            print(f"[+] Connecting to {device['ip']}...")
            connection = ConnectHandler(**device)

            # Collect show version
            version_output = connection.send_command("show version")
            hostname, model = parse_show_version(version_output)

            # Collect IP info
            ip_output = connection.send_command("show ip interface brief")
            mgmt_ip = get_management_ip(ip_output)

            summary_data.append({
                "Hostname": hostname,
                "IP Address": mgmt_ip if mgmt_ip else device["ip"],
                "Model": model
            })

            connection.disconnect()
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            print(f"[-] Failed to connect to {device['ip']}: {e}")

    # Save to CSV
    with open("topology_summary.csv", mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Hostname", "IP Address", "Model"])
        writer.writeheader()
        for row in summary_data:
            writer.writerow(row)

    print("[+] Topology summary saved as 'topology_summary.csv'")

if __name__ == "__main__":
    main()

#3 Group devices by platform

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



