# Backup running-config to local storage / Cisco specific script
# Output creates a backups/ folder if it does not already exist, the output itself is saved along the lines of "R1_running-config_20240520-230133.txt"

from netmiko import ConnectHandler
from datetime import datetime
import os

# Define Cisco IOS Device Credentials
device = {
    "device_type": "cisco_ios",
    "ip": "192.168.1.1",
    "username": "admin",
    "password": "cisco123",
}

def backup_running_config(device):
    try:
        # Establish SSH connection to the device
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")

        print(f"Connected to {hostname} ({device['ip']})")

        # Run command to retrieve the running configuration
        output = connection.send_command("show running-config")

        # Generate filename with timestamp and hostname
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{hostname}_running-config_{timestamp}.txt"

        # Ensure the backups/ directory exists
        os.makedirs("backups", exist_ok=True)

        # Save config to file
        with open(f"backups/{filename}", "w") as file:
            file.write(output)

        print(f"Config saved as backups/{filename}")
        connection.disconnect()

    except Exception as e:
        print(f"Failed to back up {device['ip']}: {e}")

if __name__ == "__main__":
    backup_running_config(device)

# 2: Push a standardized banner to all devices
# Script is cisco specific 

from netmiko import ConnectHandler
from datetime import datetime

device = {
    "device_type": "cisco_ios",
    "ip": "192.168.1.1",
    "username": "admin",
    "password": "cisco123"
}

banner_message = "Unauthorized access is prohibited. All activity is monitored."

def push_banner(device, message):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")

        print(f"[+] Connected to {hostname} ({device['ip']})")

        commands = [
            f"banner motd ^{message}^"
        ]

        output = connection.send_config_set(commands)
        print(f"[+] Banner pushed to {hostname}\n{output}")
        connection.save_config()
        connection.disconnect()

    except Exception as e:
        print(f"[!] Failed to configure banner on {device['ip']}: {e}")

if __name__ == "__main__":
    push_banner(device, banner_message)

# 3:  Automate hostname updates from a CSV (cisco specific)

# CSV Example
ip,username,password,new_hostname
192.168.1.1,admin,cisco123,R1
192.168.1.2,admin,cisco123,R2

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

def update_hostname(ip, username, password, new_hostname):
    device = {
        "device_type": "cisco_ios",
        "ip": ip,
        "username": username,
        "password": password,
    }

    try:
        connection = ConnectHandler(**device)
        old_prompt = connection.find_prompt()
        print(f"[+] Connected to {old_prompt.strip()} ({ip})")

        # Enter config mode and update hostname
        commands = [
            f"hostname {new_hostname}"
        ]
        connection.send_config_set(commands)

        # Save the config
        connection.save_config()

        print(f"[+] Hostname changed to {new_hostname} and saved.")
        connection.disconnect()
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {ip}: {e}")

def main():
    with open("hostnames.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            ip = row["ip"]
            username = row["username"]
            password = row["password"]
            new_hostname = row["new_hostname"]

            update_hostname(ip, username, password, new_hostname)

if __name__ == "__main__":
    main()

# SSH Key rather than using a password

# CSV example
ip,username,new_hostname,key_file
192.168.1.1,admin,R1,/home/youruser/.ssh/id_rsa
192.168.1.2,admin,R2,/home/youruser/.ssh/id_rsa

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

def update_hostname(ip, username, new_hostname, key_file):
    device = {
        "device_type": "cisco_ios",
        "ip": ip,
        "username": username,
        "use_keys": True,
        "key_file": key_file,
    }

    try:
        connection = ConnectHandler(**device)
        old_prompt = connection.find_prompt()
        print(f"[+] Connected to {old_prompt.strip()} ({ip})")

        # Change hostname and save
        commands = [
            f"hostname {new_hostname}"
        ]
        connection.send_config_set(commands)
        connection.save_config()

        print(f"[+] Hostname changed to {new_hostname} and saved.")
        connection.disconnect()
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Connection failed to {ip}: {e}")

def main():
    with open("hostnames.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            ip = row["ip"]
            username = row["username"]
            new_hostname = row["new_hostname"]
            key_file = row.get("key_file", "/home/youruser/.ssh/id_rsa")  # default fallback

            update_hostname(ip, username, new_hostname, key_file)

if __name__ == "__main__":
    main()

# 4: Configure interface descriptions in bulk / cisco specific 

# interface_descriptions.csv 
ip,username,interface,description
192.168.1.1,admin,GigabitEthernet0/1,Link to Core Switch
192.168.1.1,admin,GigabitEthernet0/2,Server Farm Uplink
192.168.1.2,admin,GigabitEthernet0/1,Access Switch Connection

import csv
from collections import defaultdict
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

def configure_descriptions(device_info, interface_cmds):
    device = {
        "device_type": "cisco_ios",
        "ip": device_info["ip"],
        "username": device_info["username"],
        "use_keys": True,
        "key_file": device_info.get("key_file", "/home/youruser/.ssh/id_rsa"),  # default key file
    }

    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        full_commands = []
        for intf, desc in interface_cmds:
            full_commands.append(f"interface {intf}")
            full_commands.append(f"description {desc}")

        connection.send_config_set(full_commands)
        connection.save_config()
        print(f"[+] Updated {len(interface_cmds)} interface(s) on {hostname}.")

        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    device_interface_map = defaultdict(list)

    with open("interface_descriptions.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = (row["ip"], row["username"], row.get("key_file", "/home/youruser/.ssh/id_rsa"))
            device_interface_map[key].append((row["interface"], row["description"]))

    for (ip, username, key_file), interfaces in device_interface_map.items():
        device_info = {
            "ip": ip,
            "username": username,
            "key_file": key_file
        }
        configure_descriptions(device_info, interfaces)

if __name__ == "__main__":
    main()

# 5: Deploy NTP server configs across all routers

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Replace with your actual NTP server(s)
NTP_SERVERS = [
    "ntp server 192.168.100.1",
    "ntp server 192.168.100.2"
]

def configure_ntp(device_info):
    device = {
        "device_type": "cisco_ios",
        "ip": device_info["ip"],
        "username": device_info["username"],
        "use_keys": True,
        "key_file": device_info["key_file"],
    }

    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        # Enter configuration mode and apply NTP settings
        output = connection.send_config_set(NTP_SERVERS)
        print(f"[+] NTP configuration sent to {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    with open("ntp_devices.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device_info = {
                "ip": row["ip"],
                "username": row["username"],
                "key_file": row.get("key_file", "/home/youruser/.ssh/id_rsa")
            }
            configure_ntp(device_info)

if __name__ == "__main__":
    main()

# 6: Push SNMP configurations to switches

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Define the SNMP configuration to apply
snmp_config = [
    "snmp-server community public RO",
    "snmp-server community private RW",
    "snmp-server location DataCenter1",
    "snmp-server contact netadmin@example.com",
]

def push_snmp_config(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        output = connection.send_config_set(snmp_config)
        print(f"[+] SNMP configuration sent:\n{output}")

        connection.save_config()
        print(f"[+] Config saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Connection failed to {device['ip']}: {e}")

def main():
    with open("snmp_switches.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device = {
                "device_type": "cisco_ios",
                "ip": row["ip"],
                "username": row["username"],
                "use_keys": True,
                "key_file": row.get("key_file", "/home/youruser/.ssh/id_rsa")
            }
            push_snmp_config(device)

if __name__ == "__main__":
    main()

# 7: Enable/disable specific interfaces in bulk
# 8: Push AAA authentication config
# 9: Set up logging servers on all core devices
# 10: Apply a basic port-security config to all access ports
# 11: Configure VLANs based on site template
# 12: Deploy interface IP addresses from an Excel or YAML file





