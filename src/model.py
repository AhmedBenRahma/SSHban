"""
model.py
--------
Train a Random Forest classifier on the CICIDS2017 Tuesday dataset to detect
SSH brute-force (SSH-Patator) attacks and save the trained model artefacts.

Usage:
    python src/model.py

Outputs:
    models/model.pkl      – trained Random Forest model
    models/features.pkl   – list of feature column names used during training
"""

import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATASET_PATH = os.path.join("data", "Tuesday-WorkingHours.pcap_ISCX.csv")
MODEL_OUTPUT = os.path.join("models", "model.pkl")
FEATURES_OUTPUT = os.path.join("models", "features.pkl")

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Init_Win_bytes_forward",
    "act_data_pkt_fwd",
    "Flow IAT Mean",
    "Fwd IAT Mean",
]

TARGET_COLUMN = " Label"          # Leading space is intentional (raw CSV header)
ATTACK_LABEL = "SSH-Patator"
BENIGN_LABEL = "BENIGN"

N_ESTIMATORS = 100
RANDOM_STATE = 42
TEST_SIZE = 0.2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_dataset(path: str) -> pd.DataFrame:
    """Load and filter the CICIDS2017 Tuesday CSV."""
    print(f"[*] Loading dataset: {path}")
    df = pd.read_csv(path, low_memory=False)

    # Standardise column names (strip leading/trailing whitespace)
    df.columns = df.columns.str.strip()

    # Keep only BENIGN and SSH-Patator rows
    df = df[df["Label"].isin([BENIGN_LABEL, ATTACK_LABEL])].copy()

    print(f"    Rows after filtering: {len(df):,}")
    print(df["Label"].value_counts())
    return df


def prepare_data(df: pd.DataFrame):
    """Split into features / target and create train/test sets."""
    X = df[FEATURES].copy()
    y = (df["Label"] == ATTACK_LABEL).astype(int)   # 1 = attack, 0 = benign

    # Replace infinite values and NaNs
    X.replace([float("inf"), float("-inf")], pd.NA, inplace=True)
    X.fillna(0, inplace=True)

    return train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)


def train_model(X_train, y_train) -> RandomForestClassifier:
    """Train a Random Forest classifier."""
    print(f"[*] Training Random Forest ({N_ESTIMATORS} estimators) …")
    clf = RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE, n_jobs=-1)
    clf.fit(X_train, y_train)
    print("    Training complete.")
    return clf


def evaluate_model(clf: RandomForestClassifier, X_test, y_test) -> None:
    """Print evaluation metrics."""
    y_pred = clf.predict(X_test)
    print("\n[*] Evaluation Results")
    print(f"    Accuracy : {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print("\n    Classification Report:")
    print(classification_report(y_test, y_pred, target_names=[BENIGN_LABEL, ATTACK_LABEL]))
    print("    Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))


def save_artefacts(clf: RandomForestClassifier, features: list, model_path: str, features_path: str) -> None:
    """Persist model and feature list to disk."""
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    with open(features_path, "wb") as f:
        pickle.dump(features, f)
    print(f"\n[+] Model saved   → {model_path}")
    print(f"[+] Features saved → {features_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    df = load_dataset(DATASET_PATH)
    X_train, X_test, y_train, y_test = prepare_data(df)
    clf = train_model(X_train, y_train)
    evaluate_model(clf, X_test, y_test)
    save_artefacts(clf, FEATURES, MODEL_OUTPUT, FEATURES_OUTPUT)
