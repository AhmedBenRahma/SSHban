"""
test.py
-------
Quick check of the label distribution in the CICIDS2017 Tuesday dataset.
Prints class counts and proportions without loading the full feature matrix.

Usage:
    python utils/test.py [--path PATH]
"""

import argparse
import os

import pandas as pd

DEFAULT_PATH = os.path.join("data", "Tuesday-WorkingHours.pcap_ISCX.csv")

ATTACK_LABEL = "SSH-Patator"
BENIGN_LABEL = "BENIGN"


def check_labels(path: str) -> None:
    """Print label distribution for BENIGN and SSH-Patator rows."""
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        return

    print(f"[*] Reading labels from: {path}")
    df = pd.read_csv(path, usecols=[" Label"], low_memory=False)
    df.columns = df.columns.str.strip()

    counts = df["Label"].value_counts()
    total = len(df)

    print(f"\n{'Label':<20}  {'Count':>10}  {'Proportion':>12}")
    print("-" * 46)
    for label, count in counts.items():
        print(f"{label:<20}  {count:>10,}  {count / total:>11.2%}")

    print(f"\n{'Total':<20}  {total:>10,}")

    # Highlight the two classes of interest
    for label in [BENIGN_LABEL, ATTACK_LABEL]:
        if label in counts:
            print(f"\n  {label}: {counts[label]:,} rows")
        else:
            print(f"\n  {label}: NOT FOUND in dataset")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check label distribution in CICIDS2017 CSV.")
    parser.add_argument(
        "--path",
        type=str,
        default=DEFAULT_PATH,
        help=f"Path to the dataset CSV (default: {DEFAULT_PATH})",
    )
    args = parser.parse_args()
    check_labels(args.path)


if __name__ == "__main__":
    main()
