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

# 6: Push SNMP configurations to switches / SNMPv3 / Cisco Specific

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Define the SNMP configuration to apply
import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Define SNMPv3 config commands
snmpv3_config = [
    "snmp-server group SECUREGROUP v3 priv",
    "snmp-server user NETENG SECUREGROUP v3 auth sha SNMPAuthPass123 priv aes 128 SNMPPrivPass456",
    "snmp-server location DataCenter1",
    "snmp-server contact netadmin@example.com",
]

def push_snmpv3_config(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        output = connection.send_config_set(snmpv3_config)
        print(f"[+] SNMPv3 configuration pushed to {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Connection failed to {device['ip']}: {e}")

def main():
    with open("snmpv3_switches.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device = {
                "device_type": "cisco_ios",
                "ip": row["ip"],
                "username": row["username"],
                "use_keys": True,
                "key_file": row.get("key_file", "/home/youruser/.ssh/id_rsa")
            }
            push_snmpv3_config(device)

if __name__ == "__main__":
    main()

#7: Enable/disable specific interfaces in bulk

import csv
from collections import defaultdict
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

def toggle_interfaces(device_info, interface_actions):
    device = {
        "device_type": "cisco_ios",
        "ip": device_info["ip"],
        "username": device_info["username"],
        "use_keys": True,
        "key_file": device_info["key_file"]
    }

    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        config_commands = []
        for intf, action in interface_actions:
            config_commands.append(f"interface {intf}")
            if action.lower() == "disable":
                config_commands.append("shutdown")
            elif action.lower() == "enable":
                config_commands.append("no shutdown")
            else:
                print(f"[!] Unknown action '{action}' for {intf}")

        output = connection.send_config_set(config_commands)
        print(f"[+] Applied interface changes on {hostname}:\n{output}")
        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")

        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Connection failed to {device['ip']}: {e}")

def main():
    device_interface_map = defaultdict(list)

    with open("interface_toggle.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = (row["ip"], row["username"], row["key_file"])
            device_interface_map[key].append((row["interface"], row["action"]))

    for (ip, username, key_file), interfaces in device_interface_map.items():
        device_info = {
            "ip": ip,
            "username": username,
            "key_file": key_file
        }
        toggle_interfaces(device_info, interfaces)

if __name__ == "__main__":
    main()


# 8: Push AAA authentication config

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

# Customize this with your actual RADIUS server details
RADIUS_SERVER = "192.168.100.10"
RADIUS_SECRET = "RADIUS_SECRET123"

aaa_config = [
    "aaa new-model",
    "aaa authentication login default group radius local",
    "aaa authorization exec default group radius local",
    f"radius-server host {RADIUS_SERVER} auth-port 1812 acct-port 1813 key {RADIUS_SECRET}"
]

def push_aaa_config(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        output = connection.send_config_set(aaa_config)
        print(f"[+] AAA config pushed to {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Config saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Connection failed to {device['ip']}: {e}")

def main():
    with open("aaa_devices.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device = {
                "device_type": "cisco_ios",
                "ip": row["ip"],
                "username": row["username"],
                "use_keys": True,
                "key_file": row.get("key_file", "/home/youruser/.ssh/id_rsa")
            }
            push_aaa_config(device)

if __name__ == "__main__":
    main()

# 9: Set up logging servers on all core devices

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

# Define your syslog/logging server(s) and optional config
LOGGING_SERVERS = [
    "logging host 192.168.200.10",
    "logging trap warnings",
    "service timestamps log datetime msec",
    "logging buffered 8192"
]

def configure_logging(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        output = connection.send_config_set(LOGGING_SERVERS)
        print(f"[+] Logging config pushed to {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    with open("core_devices.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device = {
                "device_type": "cisco_ios",
                "ip": row["ip"],
                "username": row["username"],
                "use_keys": True,
                "key_file": row.get("key_file", "/home/youruser/.ssh/id_rsa")
            }
            configure_logging(device)

if __name__ == "__main__":
    main()

#10: Apply a basic port-security config to all access ports

import csv
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

# Port-security commands to apply to each access port
port_security_config = [
    "switchport port-security",
    "switchport port-security maximum 2",
    "switchport port-security violation restrict",
    "switchport port-security mac-address sticky"
]

def get_access_ports(connection):
    output = connection.send_command("show interfaces switchport", use_textfsm=True)
    access_ports = []
    for intf in output:
        if intf["switchport_mode"] == "access":
            access_ports.append(intf["interface"])
    return access_ports

def apply_port_security(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        access_ports = get_access_ports(connection)
        print(f"[+] Found {len(access_ports)} access port(s) on {hostname}")

        if not access_ports:
            print(f"[!] No access ports found on {hostname}. Skipping.")
            connection.disconnect()
            return

        config_commands = []
        for port in access_ports:
            config_commands.append(f"interface {port}")
            config_commands.extend(port_security_config)

        output = connection.send_config_set(config_commands)
        print(f"[+] Port-security applied on {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    with open("portsecurity_switches.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device = {
                "device_type": "cisco_ios",
                "ip": row["ip"],
                "username": row["username"],
                "use_keys": True,
                "key_file": row["key_file"]
            }
            apply_port_security(device)

if __name__ == "__main__":
    main()

#11: Configure VLANs based on site template

import csv
from collections import defaultdict
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

def configure_vlans(device_info, vlan_list):
    device = {
        "device_type": "cisco_ios",
        "ip": device_info["ip"],
        "username": device_info["username"],
        "use_keys": True,
        "key_file": device_info["key_file"]
    }

    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        commands = []
        for vlan_id, vlan_name in vlan_list:
            commands.append(f"vlan {vlan_id}")
            commands.append(f"name {vlan_name}")

        output = connection.send_config_set(commands)
        print(f"[+] VLANs configured on {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    site_vlan_map = defaultdict(list)

    with open("site_vlan_template.csv", mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = (row["ip"], row["username"], row["key_file"])
            site_vlan_map[key].append((row["vlan_id"], row["vlan_name"]))

    for (ip, username, key_file), vlan_list in site_vlan_map.items():
        device_info = {
            "ip": ip,
            "username": username,
            "key_file": key_file
        }
        configure_vlans(device_info, vlan_list)

if __name__ == "__main__":
    main()

#12: Deploy interface IP addresses from an Excel or YAML file

#YAML
import yaml
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

def configure_interfaces(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        commands = []
        for intf in device["interfaces"]:
            commands.append(f"interface {intf['interface']}")
            commands.append(f"ip address {intf['ip_address']} {intf['subnet_mask']}")
            commands.append("no shutdown")

        output = connection.send_config_set(commands)
        print(f"[+] IP addresses applied on {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    with open("interface_ips.yaml", "r") as f:
        devices = yaml.safe_load(f)

    for device in devices:
        device_config = {
            "device_type": "cisco_ios",
            "ip": device["ip"],
            "username": device["username"],
            "use_keys": True,
            "key_file": device["key_file"],
            "interfaces": device["interfaces"]
        }
        configure_interfaces(device_config)

if __name__ == "__main__":
    main()

#Excel
import openpyxl
from collections import defaultdict
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException

def configure_interfaces(device_info, interfaces):
    device = {
        "device_type": "cisco_ios",
        "ip": device_info["ip"],
        "username": device_info["username"],
        "use_keys": True,
        "key_file": device_info["key_file"]
    }

    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")
        print(f"[+] Connected to {hostname} ({device['ip']})")

        commands = []
        for intf, ip_addr, mask in interfaces:
            commands.append(f"interface {intf}")
            commands.append(f"ip address {ip_addr} {mask}")
            commands.append("no shutdown")

        output = connection.send_config_set(commands)
        print(f"[+] IP addresses applied on {hostname}:\n{output}")

        connection.save_config()
        print(f"[+] Configuration saved on {hostname}.\n")
        connection.disconnect()

    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[-] Failed to connect to {device['ip']}: {e}")

def main():
    wb = openpyxl.load_workbook("interface_ips.xlsx")
    sheet = wb.active

    device_map = defaultdict(list)
    for row in sheet.iter_rows(min_row=2, values_only=True):
        ip, username, key_file, interface, ip_address, subnet_mask = row
        device_key = (ip, username, key_file)
        device_map[device_key].append((interface, ip_address, subnet_mask))

    for (ip, username, key_file), interfaces in device_map.items():
        device_info = {
            "ip": ip,
            "username": username,
            "key_file": key_file
        }
        configure_interfaces(device_info, interfaces)

if __name__ == "__main__":
    main()




