# static_route_builder.py

#1: Imports & Setup
# - argparse, csv, yaml, logger

#2: Load Routes
# - Load destination networks, masks, and next hops from YAML or CSV

#3: Generate Config
# - Create 'ip route' CLI commands for each route

#4: Annotate Results
# - Add destination, mask, next hop, and generated config line

#5: Export
# - Write results to CSV

import argparse
import csv
import yaml
from typing import List, Dict
from utils.logger import setup_logger

def load_routes_file(file_path: str) -> List[Dict[str, str]]:
    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        routes = []
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                routes.append(row)
        return routes

def generate_static_route_config(route: Dict[str, str]) -> str:
    destination = route['destination']
    mask = route['mask']
    next_hop = route['next_hop']
    return f"ip route {destination} {mask} {next_hop}"

def process_routes(routes: List[Dict[str, str]], logger) -> List[Dict[str, str]]:
    results = []
    for route in routes:
        config = generate_static_route_config(route)
        logger.info(f"Generated static route: {config}")
        results.append({
            "Destination": route['destination'],
            "Mask": route['mask'],
            "Next Hop": route['next_hop'],
            "Generated Config": config
        })
    return results

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = data[0].keys()
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Build static route configurations from YAML or CSV input")
    parser.add_argument('--input_file', required=True, help="YAML or CSV file with static routes")
    parser.add_argument('--output', required=True, help="CSV output file with generated configs")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("static_route_builder", level=args.log_level)

    routes = load_routes_file(args.input_file)
    results = process_routes(routes, logger)

    export_to_csv(results, args.output)
    logger.info(f"Static route configurations saved to {args.output}")

if __name__ == '__main__':
    main()

