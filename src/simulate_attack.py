"""
simulate_attack.py
------------------
Simulates a synthetic SSH-Patator brute-force flow and appends it to
`flow_en_direct.csv` so you can observe real-time detection in the dashboard
without running an actual attack.

Usage:
    python src/simulate_attack.py [--count N]

Options:
    --count N   Number of synthetic attack flows to append (default: 1)
"""

import argparse
import os
import random

import pandas as pd

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LIVE_FLOW_PATH = "flow_en_direct.csv"

# Representative SSH-Patator flow values derived from the CICIDS2017 dataset
ATTACK_FLOW_TEMPLATE = {
    "Flow Duration": 0.0,
    "Total Fwd Packets": 3,
    "Total Backward Packets": 2,
    "Flow Bytes/s": 8500.0,
    "Flow Packets/s": 850.0,
    "Average Packet Size": 62.0,
    "Avg Fwd Segment Size": 62.0,
    "Init_Win_bytes_forward": 8192,
    "act_data_pkt_fwd": 1,
    "Flow IAT Mean": 1200.0,
    "Fwd IAT Mean": 1100.0,
}

# Representative BENIGN flow values
BENIGN_FLOW_TEMPLATE = {
    "Flow Duration": 120000000.0,
    "Total Fwd Packets": 15,
    "Total Backward Packets": 12,
    "Flow Bytes/s": 1200.0,
    "Flow Packets/s": 120.0,
    "Average Packet Size": 800.0,
    "Avg Fwd Segment Size": 800.0,
    "Init_Win_bytes_forward": 65535,
    "act_data_pkt_fwd": 8,
    "Flow IAT Mean": 800000.0,
    "Fwd IAT Mean": 700000.0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def jitter(value: float, pct: float = 0.10) -> float:
    """Add ±pct random noise to a numeric value."""
    if isinstance(value, float):
        delta = value * pct * random.uniform(-1, 1)
        return round(value + delta, 4)
    return value


def make_flow(template: dict) -> dict:
    """Return a flow dict with small random perturbations."""
    return {k: jitter(v) for k, v in template.items()}


def append_flows(flows: "list[dict]", path: str) -> None:
    """Append a list of flow dicts to the live flow CSV."""
    df = pd.DataFrame(flows)
    write_header = not os.path.exists(path)
    df.to_csv(path, mode="a", header=write_header, index=False)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate SSH brute-force flows for demo.")
    parser.add_argument("--count", type=int, default=1, help="Number of attack flows to append.")
    parser.add_argument(
        "--benign", type=int, default=0, help="Number of benign flows to append alongside attacks."
    )
    args = parser.parse_args()

    flows = []
    for _ in range(args.count):
        flows.append(make_flow(ATTACK_FLOW_TEMPLATE))
    for _ in range(args.benign):
        flows.append(make_flow(BENIGN_FLOW_TEMPLATE))

    random.shuffle(flows)
    append_flows(flows, LIVE_FLOW_PATH)

    print(f"[+] Appended {args.count} attack flow(s) and {args.benign} benign flow(s) to '{LIVE_FLOW_PATH}'.")


if __name__ == "__main__":
    main()
