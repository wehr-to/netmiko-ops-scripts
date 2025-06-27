# Run traceroute from all edge routers
# connects to multiple source devices, runs traceroute to target IPs, collects hop paths, and exports results to CSV.

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
from logger import setup_logger
from conn.netmiko_conn import connect_device_with_retries
from parsers.inventory_parser import load_yaml_inventory, validate_ip


def build_traceroute_commands(targets: List[str]) -> List[str]:
    return [f"traceroute {ip}" for ip in targets]


def execute_traceroutes(device: Dict[str, str], targets: List[str], logger) -> List[Dict[str, str]]:
    ip = device['host']
    hostname = device.get('hostname', ip)
    try:
        trace_cmds = build_traceroute_commands(targets)
        ip, output = connect_device_with_retries(
            device,
            commands=trace_cmds,
            config_commands=[],
            retries=2,
            delay=2,
            debug=False
        )
        results = []
        outputs = output.split('traceroute')
        for i, target in enumerate(targets):
            trace_result = outputs[i + 1] if i + 1 < len(outputs) else ''
            trace_lines = trace_result.strip().splitlines()
            hops = "; ".join(line.strip() for line in trace_lines if line.strip())
            status = "Success" if hops else "No response"
            results.append({
                "Source IP": ip,
                "Hostname": hostname,
                "Target": target,
                "Status": status,
                "Path": hops
            })
        logger.info(f"{ip}: Completed traceroute tests to {len(targets)} targets")
        return results
    except Exception as e:
        logger.error(f"{ip}: Traceroute failed - {e}")
        return [{"Source IP": ip, "Hostname": hostname, "Target": "ALL", "Status": "ERROR", "Path": str(e)}]


def export_to_csv(results: List[Dict[str, str]], output_file: str):
    if not results:
        return
    fields = sorted(results[0].keys())
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def main():
    parser = argparse.ArgumentParser(description="Distributed traceroute test across devices")
    parser.add_argument('--inventory', required=True, help="YAML inventory of source devices")
    parser.add_argument('--targets', required=True, help="Path to text file of target IPs")
    parser.add_argument('--output', required=True, help="CSV file for results")
    parser.add_argument('--threads', type=int, default=10)
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("traceroute_test", level=args.log_level)
    devices = load_yaml_inventory(args.inventory)
    devices = [d for d in devices if validate_ip(d)]

    with open(args.targets) as f:
        targets = [line.strip() for line in f if line.strip()]

    all_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_device = {
            executor.submit(execute_traceroutes, device, targets, logger): device['host']
            for device in devices
        }
        for future in as_completed(future_to_device):
            all_results.extend(future.result())

    export_to_csv(all_results, args.output)
    logger.info(f"Distributed traceroute test complete. Results saved to {args.output}")


if __name__ == '__main__':
    main()

#1: CLI Args
# --inventory: YAML devices (sources)
# --targets: target IPs file
# --output: CSV file
# --threads: concurrency
# --log_level

#2: Load Inventory & Targets
# - Validate device IPs

#3: For Each Device (Threaded)
# - Build and run 'traceroute <target>'
# - Parse hop-by-hop output
# - Record hops and success/fail

#4: Write results to CSV

#5: main()

