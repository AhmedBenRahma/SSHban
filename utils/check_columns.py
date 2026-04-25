"""
check_columns.py
----------------
Utility script to inspect the column names of the CICIDS2017 dataset CSV.
Useful to verify the exact header strings before training the model.

Usage:
    python utils/check_columns.py [--path PATH]
"""

import argparse
import os

import pandas as pd

DEFAULT_PATH = os.path.join("data", "Tuesday-WorkingHours.pcap_ISCX.csv")


def check_columns(path: str) -> None:
    """Print all column names and their data types."""
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        return

    print(f"[*] Reading columns from: {path}")
    # Only read the header row for efficiency
    df = pd.read_csv(path, nrows=0)
    columns = df.columns.tolist()

    print(f"\n{'Index':<6}  {'Column Name'}")
    print("-" * 50)
    for i, col in enumerate(columns):
        print(f"{i:<6}  '{col}'")

    print(f"\nTotal columns: {len(columns)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect CICIDS2017 CSV column names.")
    parser.add_argument(
        "--path",
        type=str,
        default=DEFAULT_PATH,
        help=f"Path to the dataset CSV (default: {DEFAULT_PATH})",
    )
    args = parser.parse_args()
    check_columns(args.path)


if __name__ == "__main__":
    main()
