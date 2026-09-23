"""Live detection: score new network flows and raise alerts.

``LiveAnalyzer`` tails a flow CSV (produced live by CICFlowMeter, or by the
bundled ``simulate`` command), scores every new row with the trained model, and
appends one line to ``alerts.csv`` per detected attack flow. The Streamlit
dashboard reads that alert feed.

The scoring logic is factored out of the polling loop so it can be unit-tested
without any files or timers.
"""
from __future__ import annotations

import argparse
import pickle
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

from .features import load_features

ALERT_TYPE = "SSH Brute Force"


@dataclass
class Alert:
    time: str
    attack_type: str
    src_ip: str

    def to_csv_line(self) -> str:
        return f"{self.time},{self.attack_type},{self.src_ip}\n"


class LiveAnalyzer:
    """Loads the model once and scores batches of flows."""

    def __init__(
        self,
        model_path: str | Path = "models/model.pkl",
        features_path: str | Path = "models/features.pkl",
    ) -> None:
        with open(model_path, "rb") as fh:
            self.model = pickle.load(fh)
        self.features = load_features(features_path)

    def predict(self, flows: pd.DataFrame) -> list[int]:
        """Return a 0/1 prediction for each flow (1 = attack)."""
        flows = flows.copy()
        flows.columns = flows.columns.str.strip()
        missing = [f for f in self.features if f not in flows.columns]
        if missing:
            raise KeyError(f"flow data is missing required features: {missing}")
        X = flows[self.features].fillna(0)
        return [int(p) for p in self.model.predict(X)]

    def alerts_for(self, flows: pd.DataFrame) -> list[Alert]:
        """Score a batch and return an Alert for every flow classified as attack."""
        flows = flows.reset_index(drop=True)
        preds = self.predict(flows)
        now = datetime.now().strftime("%H:%M:%S")
        out: list[Alert] = []
        for i, pred in enumerate(preds):
            if pred == 1:
                src = str(flows.iloc[i].get("Src IP", "unknown"))
                out.append(Alert(now, ALERT_TYPE, src))
        return out


def watch(
    flow_csv: str | Path = "flow_en_direct.csv",
    alerts_csv: str | Path = "alerts.csv",
    poll_seconds: float = 2.0,
    model_path: str | Path = "models/model.pkl",
    features_path: str | Path = "models/features.pkl",
) -> None:
    """Poll ``flow_csv`` for new rows and append detections to ``alerts_csv``."""
    analyzer = LiveAnalyzer(model_path, features_path)
    flow_csv, alerts_csv = Path(flow_csv), Path(alerts_csv)
    print(f"[sshban] live analyzer started — watching {flow_csv}")
    seen = 0
    while True:
        if flow_csv.exists():
            try:
                df = pd.read_csv(flow_csv)
                if len(df) > seen:
                    new = df.iloc[seen:]
                    seen = len(df)
                    for alert in analyzer.alerts_for(new):
                        print(f"[ALERT] {alert.attack_type} from {alert.src_ip}")
                        with open(alerts_csv, "a") as fh:
                            fh.write(alert.to_csv_line())
            except (pd.errors.EmptyDataError, PermissionError):
                pass  # file mid-write; retry next tick
        time.sleep(poll_seconds)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score live flows and raise SSH alerts.")
    ap.add_argument("--flow", default="flow_en_direct.csv")
    ap.add_argument("--alerts", default="alerts.csv")
    ap.add_argument("--poll", type=float, default=2.0)
    ap.add_argument("--model", default="models/model.pkl")
    ap.add_argument("--features", default="models/features.pkl")
    args = ap.parse_args(argv)
    watch(args.flow, args.alerts, args.poll, args.model, args.features)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
