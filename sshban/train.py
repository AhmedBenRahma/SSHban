"""Train the SSH brute-force detector on the CICIDS2017 capture.

The Tuesday capture of CICIDS2017 contains labelled BENIGN traffic and a real
SSH-Patator brute-force campaign. We keep only those two classes and train a
Random Forest on the flow-shape features defined in ``features.py``.

Usage:
    python -m sshban.train --data Tuesday-WorkingHours.pcap_ISCX.csv

The dataset is not shipped with the repository (it is large and publicly
available); see docs/DATASET.md for the download link.
"""
from __future__ import annotations

import argparse
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from .features import FEATURES

ATTACK_LABEL = "SSH-Patator"
BENIGN_LABEL = "BENIGN"


def load_dataset(csv_path: str | Path) -> pd.DataFrame:
    """Load the CICIDS2017 CSV and keep only BENIGN and SSH-Patator flows."""
    df = pd.read_csv(csv_path, encoding="utf-8", low_memory=False)
    df.columns = df.columns.str.strip()
    df = df[df["Label"].isin([BENIGN_LABEL, ATTACK_LABEL])].copy()
    df["target"] = (df["Label"] == ATTACK_LABEL).astype(int)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
    return df


def train(
    csv_path: str | Path,
    model_out: str | Path = "models/model.pkl",
    features_out: str | Path = "models/features.pkl",
    n_estimators: int = 100,
    random_state: int = 42,
) -> RandomForestClassifier:
    """Train, evaluate, and persist the detector."""
    df = load_dataset(csv_path)
    print(f"[data] {len(df):,} flows kept "
          f"({int(df.target.sum()):,} attack / {int((df.target == 0).sum()):,} benign)")

    X, y = df[FEATURES], df["target"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=n_estimators, random_state=random_state, n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n=== Held-out evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["Benign", ATTACK_LABEL]))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

    Path(model_out).parent.mkdir(parents=True, exist_ok=True)
    with open(model_out, "wb") as fh:
        pickle.dump(clf, fh)
    with open(features_out, "wb") as fh:
        pickle.dump(FEATURES, fh)
    print(f"\n[saved] {model_out} · {features_out}")
    return clf


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train the SSHban SSH brute-force detector.")
    ap.add_argument("--data", default="Tuesday-WorkingHours.pcap_ISCX.csv",
                    help="Path to the CICIDS2017 Tuesday CSV.")
    ap.add_argument("--model-out", default="models/model.pkl")
    ap.add_argument("--features-out", default="models/features.pkl")
    ap.add_argument("--n-estimators", type=int, default=100)
    args = ap.parse_args(argv)
    train(args.data, args.model_out, args.features_out, args.n_estimators)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
