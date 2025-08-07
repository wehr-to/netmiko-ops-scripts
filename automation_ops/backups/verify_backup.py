import argparse
from pathlib import Path
import gzip
import re
import csv
from typing import List
from utils.logger import setup_logger


def list_backup_files(directory: Path, extension: str = ".gz") -> List[Path]:
    return sorted([f for f in directory.glob(f"*{extension}") if f.is_file()])


def verify_backup_content(file_path: Path, logger, pattern: str) -> str:
    try:
        with gzip.open(file_path, 'rt') as f:
            content = f.read()
            if re.search(pattern, content, re.IGNORECASE):
                return "VALID"
            else:
                return "EMPTY or INVALID"
    except Exception as e:
        logger.error(f"{file_path.name}: Error reading file - {e}")
        return "ERROR"


def export_results_to_csv(results: List[dict], csv_path: Path):
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["File", "Status"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Verify backup configuration files")
    parser.add_argument('--dir', required=True, help="Directory containing backup .gz files")
    parser.add_argument('--log_level', default="INFO", help="Logging level")
    parser.add_argument('--csv', help="Optional CSV file to save results")
    parser.add_argument('--pattern', default="version|hostname", help="Regex pattern to verify backup content")
    args = parser.parse_args()

    logger = setup_logger("verify_backups", level=args.log_level)
    backup_dir = Path(args.dir)

    if not backup_dir.exists() or not backup_dir.is_dir():
        logger.error(f"Backup directory not found: {args.dir}")
        return

    files = list_backup_files(backup_dir)
    logger.info(f"Verifying {len(files)} backup files in {backup_dir}...")

    results = []
    for file_path in files:
        status = verify_backup_content(file_path, logger, args.pattern)
        logger.info(f"{file_path.name}: {status}")
        results.append({"File": file_path.name, "Status": status})

    if args.csv:
        export_results_to_csv(results, Path(args.csv))
        logger.info(f"Verification results exported to {args.csv}")


if __name__ == '__main__':
    main()

#1: Setup & Imports
# - Import regex, gzip, csv, argparse, logging

#2: File Listing
# - Get all `.gz` backup files from given directory

#3: Content Verification
# - For each file, decompress and scan for regex pattern
# - Return: VALID / EMPTY or INVALID / ERROR

#4: Optional CSV Export
# - If `--csv` is set, write results (filename, status) to CSV

#5: CLI Interface
# - Parse: --dir, --log_level, --csv, --pattern
# - Verify each file and log result
# - Optionally export summary

#6: Entry Point
# - Call main()

