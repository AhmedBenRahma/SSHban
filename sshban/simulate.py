"""Generate a demo flow stream (benign traffic, then an attack burst).

This lets anyone see the full pipeline end to end without a Kali VM: run this in
one terminal and ``sshban detect`` + the dashboard in others. Benign flows carry
small, human-looking feature values; attack flows carry the extreme, machine-gun
values characteristic of an SSH-Patator brute-force session.
"""
from __future__ import annotations

import argparse
import random
import time
from pathlib import Path

import pandas as pd

from .features import load_features

BENIGN_IP = "192.168.1.50"
ATTACKER_IP = "205.174.165.73"  # the SSH-Patator source in CICIDS2017

# Flow signatures the *trained model* actually classifies as benign / attack.
# These were derived from the model's own learned decision regions (not guessed),
# so the demo genuinely exercises the classifier rather than a hard-coded rule.
# Attack: short flow, very few packets, high packet rate, SSH-typical window.
ATTACK_FLOW = {
    "Flow Duration": 1000.0, "Total Fwd Packets": 2, "Total Backward Packets": 2,
    "Flow Bytes/s": 0.0, "Flow Packets/s": 10000.0, "Average Packet Size": 0.0,
    "Avg Fwd Segment Size": 0.0, "Init_Win_bytes_forward": 29200,
    "act_data_pkt_fwd": 10, "Flow IAT Mean": 100.0, "Fwd IAT Mean": 1000.0,
}
# Benign: a long, chatty human SSH session.
BENIGN_FLOW = {
    "Flow Duration": 5.0e6, "Total Fwd Packets": 45, "Total Backward Packets": 40,
    "Flow Bytes/s": 4000.0, "Flow Packets/s": 30.0, "Average Packet Size": 180.0,
    "Avg Fwd Segment Size": 110.0, "Init_Win_bytes_forward": 64240,
    "act_data_pkt_fwd": 22, "Flow IAT Mean": 120000.0, "Fwd IAT Mean": 120000.0,
}


def _jitter(template: dict, features: list[str]) -> dict:
    """Add small noise to float fields so rows aren't identical (stays in class)."""
    row = {}
    for f in features:
        v = template[f]
        row[f] = v * random.uniform(0.94, 1.06) if isinstance(v, float) else v
    return row


def run(
    flow_csv: str | Path = "flow_en_direct.csv",
    features_path: str | Path = "models/features.pkl",
    benign: int = 3,
    attack: int = 5,
    delay: float = 2.0,
) -> None:
    features = load_features(features_path)
    columns = ["Src IP"] + features
    flow_csv = Path(flow_csv)
    pd.DataFrame(columns=columns).to_csv(flow_csv, index=False)
    print(f"[simulate] writing to {flow_csv}")

    for i in range(benign):
        row = {"Src IP": BENIGN_IP, **_jitter(BENIGN_FLOW, features)}
        pd.DataFrame([row]).to_csv(flow_csv, mode="a", header=False, index=False)
        print(f"  benign flow {i + 1}/{benign}")
        time.sleep(delay)

    print(f"[simulate] launching attack burst from {ATTACKER_IP}")
    for i in range(attack):
        row = {"Src IP": ATTACKER_IP, **_jitter(ATTACK_FLOW, features)}
        pd.DataFrame([row]).to_csv(flow_csv, mode="a", header=False, index=False)
        print(f"  attack flow {i + 1}/{attack}")
        time.sleep(delay)
    print("[simulate] done — watch the analyzer and dashboard")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Emit a demo flow stream for SSHban.")
    ap.add_argument("--flow", default="flow_en_direct.csv")
    ap.add_argument("--features", default="models/features.pkl")
    ap.add_argument("--benign", type=int, default=3)
    ap.add_argument("--attack", type=int, default=5)
    ap.add_argument("--delay", type=float, default=2.0)
    args = ap.parse_args(argv)
    run(args.flow, args.features, args.benign, args.attack, args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
