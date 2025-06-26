# YAML/Excel/IP list parsing

import yaml
import pandas as pd
import ipaddress
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from pathlib import Path


def load_yaml_inventory(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def load_excel_inventory(file_path):
    df = pd.read_excel(file_path)
    return df.to_dict(orient='records')


def load_ip_list(file_path, device_type, username, password):
    with open(file_path, 'r') as f:
        return [
            {
                'device_type': device_type,
                'host': line.strip(),
                'username': username,
                'password': password
            }
            for line in f if line.strip()
        ]


def validate_ip(device):
    try:
        ipaddress.ip_address(device['host'])
        return True
    except ValueError:
        return False


def connect_device(device):
    ip = device.get('host')
    try:
        conn = ConnectHandler(**device)
        output = conn.send_command("show version")
        conn.disconnect()
        return (ip, 'Success')
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        return (ip, f'Failed: {str(e)}')


def main():
    parser = argparse.ArgumentParser(description="Network Automation Inventory Parser")
    parser.add_argument('--file', required=True, help="Input file path (YAML, Excel, or IP list)")
    parser.add_argument('--type', choices=['yaml', 'excel', 'iplist'], required=True, help="Input file type")
    parser.add_argument('--device_type', help="Device type if IP list")
    parser.add_argument('--username', help="Username if IP list")
    parser.add_argument('--password', help="Password if IP list")
    parser.add_argument('--threads', type=int, default=10, help="Number of concurrent threads")

    args = parser.parse_args()
    file_path = Path(args.file)

    if args.type == 'yaml':
        devices = load_yaml_inventory(file_path)
    elif args.type == 'excel':
        devices = load_excel_inventory(file_path)
    elif args.type == 'iplist':
        if not (args.device_type and args.username and args.password):
            parser.error("--device_type, --username and --password are required for iplist")
        devices = load_ip_list(file_path, args.device_type, args.username, args.password)
    else:
        raise ValueError("Unsupported input type")

    valid_devices = [d for d in devices if validate_ip(d)]

    print(f"[+] Connecting to {len(valid_devices)} devices...")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_ip = {executor.submit(connect_device, d): d['host'] for d in valid_devices}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
            except Exception as e:
                result = (ip, f"Exception: {e}")
            results.append(result)

    print("\n--- SUMMARY ---")
    for ip, status in results:
        print(f"{ip}: {status}")


if __name__ == '__main__':
    main()

# pseudocode

#1: Imports & Setup

# - Import necessary libraries: netmiko, yaml, openpyxl, concurrent.futures, ipaddress, pandas, argparse.

#2: Load Device Inventory

# - If YAML: parse device_type, ip, username, password
# - If Excel: load via pandas.read_excel(), expect standard headers
# - If IP list: default credentials + platform from command line args

#3: Validate Devices

# - Sanitize/validate each IP using ipaddress.ip_address()

#4: Connect to Devices (Threaded)

# - Use ThreadPoolExecutor for concurrency
# - For each device:
# - Try SSH connection via Netmiko
# - Send a simple command (e.g., show version)
# - Catch exceptions: timeout, auth failure, etc.

# 5: Output Summary

# - Print per-device result (success/fail)
# - Optionally log to a CSV or JSON
