# file: parse_ip_interface_brief.py

from netmiko import ConnectHandler
from getpass import getpass
from tabulate import tabulate


def get_device_connection():
    """Establish Netmiko connection to Cisco IOS device."""
    device = {
        "device_type": "cisco_ios",
        "host": input("Enter device IP: "),
        "username": input("Username: "),
        "password": getpass("Password: "),
    }
    return ConnectHandler(**device)


def parse_show_ip_interface_brief(output):
    """Parse 'show ip interface brief' into structured data."""
    lines = output.strip().splitlines()
    parsed = []
    
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 6:
            parsed.append({
                "Interface": parts[0],
                "IP Address": parts[1],
                "OK?": parts[2],
                "Method": parts[3],
                "Status": parts[4],
                "Protocol": parts[5]
            })
        elif len(parts) == 7:  # handles multi-word status like "administratively down"
            parsed.append({
                "Interface": parts[0],
                "IP Address": parts[1],
                "OK?": parts[2],
                "Method": parts[3],
                "Status": " ".join(parts[4:6]),
                "Protocol": parts[6]
            })

    return parsed


def main():
    connection = get_device_connection()
    output = connection.send_command("show ip interface brief")
    parsed_data = parse_show_ip_interface_brief(output)
    print("\nParsed 'show ip interface brief':\n")
    print(tabulate(parsed_data, headers="keys", tablefmt="pretty"))
    connection.disconnect()


if __name__ == "__main__":
    main()

# Import Required Modules
# netmiko for SSH connection.
# getpass to securely get the device password.
# re or parsing logic to extract structured data from command output.

# Define Device Parameters
# IP/hostname
# Username
# Password (from user input)
# Device type (e.g., cisco_ios)

# Connect to the Device using Netmiko
# Use ConnectHandler to create the SSH session.

# Send Command: show ip interface brief
# Capture output from device.

# Parse the Output into Structured Format (List of Dicts)
# Extract:
# Interface
# IP Address
# OK?
# Method
# Status
# Protocol

# Print the Parsed Data in Tabular Format
