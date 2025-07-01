# Ping test from each device to a destination
# uses Netmiko to connect to multiple devices and perform parallel ping tests to a list of targets. The results are exported to CSV.

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
from logger import setup_logger
from utils.netmiko_conn import connect_device_with_retries
from utils.input_parser import load_yaml_inventory, validate_ip


def build_ping_command(targets: List[str]) -> List[str]:
    return [f"ping {ip} repeat 3 timeout 2" for ip in targets]


def execute_pings(device: Dict[str, str], targets: List[str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        ping_cmds = build_ping_command(targets)
        ip, output = connect_device_with_retries(
            device,
            commands=ping_cmds,
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        results = []
        for idx, result in enumerate(output.split('ping')[1:]):
            tgt = targets[idx]
            status = "Success" if "Success rate is 100 percent" in result else "Failure"
            results.append({"Source IP": ip, "Hostname": hostname, "Target": tgt, "Result": status})
        logger.info(f"{ip}: Completed ping tests to {len(targets)} targets")
        return results
    except Exception as e:
        logger.error(f"{ip}: Ping test failed - {e}")
        return [{"Source IP": ip, "Hostname": hostname, "Target": "ALL", "Result": f"ERROR: {e}"}]


def export_to_csv(results: List[Dict[str, str]], output_file: str):
    if not results:
        return
    fields = sorted(results[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def main():
    parser = argparse.ArgumentParser(description="Distributed ping test across devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory of source devices")
    parser.add_argument('--targets', required=True, help="Path to text file of target IPs")
    parser.add_argument('--output', required=True, help="CSV file for results")
    parser.add_argument('--threads', type=int, default=10)
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("ping_test", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    with open(args.targets) as f:
        targets = [line.strip() for line in f if line.strip()]

    all_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_device = {
            executor.submit(execute_pings, device, targets, logger): device['host']
            for device in devices
        }
        for future in as_completed(future_to_device):
            all_results.extend(future.result())

    export_to_csv(all_results, args.output)
    logger.info(f"Distributed ping test complete. Results saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML devices (sources)
# --targets: .txt file of IPs to ping
# --output: CSV result
# --threads: concurrency level
# --log_level

#2: Load & Validate Devices
# - Load target IPs from file

#3: For Each Device (Threaded)
# - Build ping commands to all targets
# - Run all pings
# - Parse success/fail per target

#4: Export Results to CSV

#5: main()

