# summarizer.py

#1: Imports & Setup
# - argparse, csv, logger

#2: Load CSV Files
# - Load multiple CSVs for summarization

#3: Summarize
# - Count entries, unique columns, and key statistics per file

#4: Annotate Results
# - Create a summary dictionary per file

#5: Export
# - Write summary results to a CSV for reporting

import argparse
import csv
from collections import Counter
from typing import List, Dict
from utils.logger import setup_logger

def summarize_csv(file_path: str) -> Dict[str, str]:
    summary = {"File": file_path}
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            summary["Total Rows"] = str(len(rows))
            if rows:
                for key in rows[0].keys():
                    values = [row[key] for row in rows]
                    summary[f"Unique {key}"] = str(len(set(values)))
        return summary
    except Exception as e:
        summary["Error"] = str(e)
        return summary

def process_files(files: List[str], logger) -> List[Dict[str, str]]:
    results = []
    for file in files:
        result = summarize_csv(file)
        logger.log_info(f"Summarized {file}: {result}")
        results.append(result)
    return results

def export_to_csv(data: List[Dict[str, str]], output_file: str):
    if not data:
        return
    fields = set()
    for d in data:
        fields.update(d.keys())
    fields = sorted(fields)
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Summarize CSV files for reporting")
    parser.add_argument('--input_files', nargs='+', required=True, help="List of CSV files to summarize")
    parser.add_argument('--output', required=True, help="CSV output file for summary")
    parser.add_argument('--log_level', default="INFO")
    args = parser.parse_args()

    logger = setup_logger("summarizer", level=args.log_level)

    results = process_files(args.input_files, logger)
    export_to_csv(results, args.output)

    logger.log_info(f"Summary report saved to {args.output}")

if __name__ == '__main__':
    main()

