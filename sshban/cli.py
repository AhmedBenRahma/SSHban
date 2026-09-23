"""Unified command-line entry point: ``sshban <command>``.

    sshban train     --data <cicids2017.csv>   # train the detector
    sshban detect    --flow flow_en_direct.csv # score live flows -> alerts.csv
    sshban simulate                            # emit a demo flow stream
    sshban dashboard                           # launch the live SOC dashboard
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sshban", description="SSHban — SSH brute-force detection.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_train = sub.add_parser("train", help="Train the detector on CICIDS2017.")
    p_train.add_argument("--data", default="Tuesday-WorkingHours.pcap_ISCX.csv")
    p_train.add_argument("--model-out", default="models/model.pkl")
    p_train.add_argument("--features-out", default="models/features.pkl")
    p_train.add_argument("--n-estimators", type=int, default=100)

    p_detect = sub.add_parser("detect", help="Score live flows and raise alerts.")
    p_detect.add_argument("--flow", default="flow_en_direct.csv")
    p_detect.add_argument("--alerts", default="alerts.csv")
    p_detect.add_argument("--poll", type=float, default=2.0)
    p_detect.add_argument("--model", default="models/model.pkl")
    p_detect.add_argument("--features", default="models/features.pkl")

    p_sim = sub.add_parser("simulate", help="Emit a demo flow stream.")
    p_sim.add_argument("--flow", default="flow_en_direct.csv")
    p_sim.add_argument("--features", default="models/features.pkl")
    p_sim.add_argument("--benign", type=int, default=3)
    p_sim.add_argument("--attack", type=int, default=5)
    p_sim.add_argument("--delay", type=float, default=2.0)

    sub.add_parser("dashboard", help="Launch the live Streamlit dashboard.")

    args = parser.parse_args(argv)

    if args.command == "train":
        from .train import train
        train(args.data, args.model_out, args.features_out, args.n_estimators)
    elif args.command == "detect":
        from .detect import watch
        watch(args.flow, args.alerts, args.poll, args.model, args.features)
    elif args.command == "simulate":
        from .simulate import run
        run(args.flow, args.features, args.benign, args.attack, args.delay)
    elif args.command == "dashboard":
        app = Path(__file__).parent / "dashboards" / "live.py"
        return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
