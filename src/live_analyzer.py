"""
live_analyzer.py
----------------
Real-time SSH flow analyzer.

Watches `flow_en_direct.csv` for new rows, classifies each flow with the
trained Random Forest model, and appends results (including a `prediction`
column) to `alertes.csv`.

Usage:
    python src/live_analyzer.py
"""

import os
import pickle
import time

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LIVE_FLOW_PATH = "flow_en_direct.csv"
ALERTS_PATH = "alertes.csv"
MODEL_PATH = os.path.join("models", "model.pkl")
FEATURES_PATH = os.path.join("models", "features.pkl")

POLL_INTERVAL = 2          # seconds between file checks
ATTACK_LABEL = "SSH-Patator"
BENIGN_LABEL = "BENIGN"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_model():
    """Load the trained model and feature list from disk."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at '{MODEL_PATH}'. "
            "Run 'python src/model.py' first."
        )
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(FEATURES_PATH, "rb") as f:
        features = pickle.load(f)
    return model, features


def prepare_flow(df: pd.DataFrame, features: list) -> pd.DataFrame:
    """Clean and select feature columns from a flow DataFrame."""
    df.columns = df.columns.str.strip()
    X = df[features].copy()
    X.replace([float("inf"), float("-inf")], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    return X


def append_alerts(results: pd.DataFrame) -> None:
    """Append classified rows to the alerts CSV."""
    write_header = not os.path.exists(ALERTS_PATH)
    results.to_csv(ALERTS_PATH, mode="a", header=write_header, index=False)


def print_alert(row: pd.Series, prediction: int) -> None:
    label = ATTACK_LABEL if prediction == 1 else BENIGN_LABEL
    icon = "🚨" if prediction == 1 else "✅"
    duration = row.get("Flow Duration", 0)
    fwd_pkts = row.get("Total Fwd Packets", 0)
    print(f"{icon} [{label}]  Flow Duration={duration:.2f}  Fwd Packets={fwd_pkts}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    print("[*] Loading model …")
    model, features = load_model()
    print(f"[+] Model loaded. Watching '{LIVE_FLOW_PATH}' for new flows …\n")

    seen_rows = 0

    while True:
        if os.path.exists(LIVE_FLOW_PATH):
            try:
                df = pd.read_csv(LIVE_FLOW_PATH, low_memory=False)
            except pd.errors.EmptyDataError:
                time.sleep(POLL_INTERVAL)
                continue

            new_rows = df.iloc[seen_rows:]
            if len(new_rows) == 0:
                time.sleep(POLL_INTERVAL)
                continue

            X = prepare_flow(new_rows.copy(), features)
            predictions = model.predict(X)

            new_rows = new_rows.copy()
            new_rows["prediction"] = predictions
            new_rows["label"] = [ATTACK_LABEL if p == 1 else BENIGN_LABEL for p in predictions]

            append_alerts(new_rows)

            for idx, (_, row) in enumerate(new_rows.iterrows()):
                print_alert(row, predictions[idx])

            seen_rows += len(new_rows)
        else:
            print(f"[~] Waiting for '{LIVE_FLOW_PATH}' to appear …")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Live analyzer stopped.")
