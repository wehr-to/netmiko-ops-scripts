import argparse
import csv
import re
from typing import Dict, List
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip

def audit_password_settings(device: Dict[str, str], logger, exclude_users: List[str]) -> Dict[str, List[str]]:
    ip, output = connect_device_with_retries(
        device,
        commands=[
            "show run | include username",
            "show run | include password",
            "show run | include secret"
        ],
        retries=3,
        delay=2,
        debug=False
    )

    logger.info(f"Device {ip}: Checking password configuration")

    if "Failed" in output or "Exception" in output:
        logger.error(f"Device {ip} connection failed: {output}")
        return {ip: [f"FAIL: {output}"]}

    findings = []
    for line in output.splitlines():
        if any(user in line for user in exclude_users):
            continue

        if "password 7" in line:
            findings.append("Weak encryption (type 7 password)")
        elif "password" in line or "secret" in line:
            findings.append(line.strip())

            m = re.search(r'(password|secret)\s+(\d\s+)?([a-zA-Z0-9!@#$%^&*()_+=-]+)', line)
            if m:
                pwd = m.group(3)
                if len(pwd) < 8:
                    findings.append("Password too short (<8 chars)")
                if not re.search(r"[A-Z]", pwd):
                    findings.append("No uppercase letter in password")
                if not re.search(r"[a-z]", pwd):
                    findings.append("No lowercase letter in password")
                if not re.search(r"[0-9]", pwd):
                    findings.append("No digit in password")
                if not re.search(r"[!@#$%^&*()]", pwd):
                    findings.append("No special char in password")

    if not findings:
        findings.append("No password/secret found in config")

    return {ip: findings}


def export_weak_to_csv(results: List[Dict[str, List[str]]], csv_path: str):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Issue"])
        for result in results:
            for ip, issues in result.items():
                for issue in issues:
                    if any(word in issue for word in ["Weak", "too short", "No"]):
                        writer.writerow([ip, issue])


def main():
    parser = argparse.ArgumentParser(description="Password Configuration Audit Tool")
    parser.add_argument('--file', required=True, help="YAML inventory file path")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--csv', help="Path to export weak findings to CSV")
    parser.add_argument('--exclude_users', nargs='*', default=[], help="Usernames to exclude from audit (e.g. admin guest)")
    args = parser.parse_args()

    logger = setup_logger("password_audit", level=args.log_level)
    devices = load_yaml_inventory(args.file)
    devices = [d for d in devices if validate_ip(d)]

    logger.info(f"Auditing password settings on {len(devices)} devices...")
    results = []
    for device in devices:
        result = audit_password_settings(device, logger, args.exclude_users)
        results.append(result)

    logger.info("\n--- PASSWORD AUDIT SUMMARY ---")
    for r in results:
        for ip, messages in r.items():
            logger.info(f"{ip}:")
            for msg in messages:
                logger.info(f"  {msg}")

    if args.csv:
        export_weak_to_csv(results, args.csv)
        logger.info(f"Weak password issues exported to CSV: {args.csv}")


if __name__ == '__main__':
    main()

#1: Imports & Setup
# - Import logging, Netmiko wrapper, CSV, regex
# - Import custom modules for logger, connection, inventory

#2: Password Audit Logic
# - Connect to device with retry logic
# - Run config filters for 'username', 'password', 'secret'
# - Exclude matches with usernames in exclude list
# - For each password line:
#   - Detect weak encryption (type 7)
#   - Extract password via regex
#   - Check length and character class policy violations
# - Return findings per device

#3: CSV Export
# - Write only weak or policy-violating issues to a file

#4: Main Function
# - Parse CLI args (inventory file, log level, optional CSV output, excluded users)
# - Load YAML inventory, filter valid IPs
# - For each device, call audit function
# - Log results to console
# - Export findings to CSV if flag is set

#5: Run Main
# - Entry point via `main()`

