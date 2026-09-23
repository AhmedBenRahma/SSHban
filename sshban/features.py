"""Single source of truth for the flow features the model consumes.

These are CICFlowMeter / CICIDS2017 column names. They describe the *behaviour*
of a network flow, not the content of any packet and not any login counter —
which is the whole point: an attacker cannot pace an attack under a threshold
they cannot see.
"""
from __future__ import annotations

from pathlib import Path
import pickle

# Order matters: the model was trained on this exact column order.
FEATURES: list[str] = [
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

# Human-readable one-liners, used by the dashboard and docs.
FEATURE_DESCRIPTIONS: dict[str, str] = {
    "Flow Duration": "Lifetime of the flow (microseconds).",
    "Total Fwd Packets": "Packets sent client -> server.",
    "Total Backward Packets": "Packets sent server -> client.",
    "Flow Bytes/s": "Byte throughput of the flow.",
    "Flow Packets/s": "Packet rate of the flow.",
    "Average Packet Size": "Mean packet size over the flow.",
    "Avg Fwd Segment Size": "Mean forward TCP segment size.",
    "Init_Win_bytes_forward": "Initial TCP receive window advertised by the client.",
    "act_data_pkt_fwd": "Forward packets that actually carried a payload.",
    "Flow IAT Mean": "Mean inter-arrival time between packets.",
    "Fwd IAT Mean": "Mean inter-arrival time between forward packets.",
}


def load_features(path: str | Path = "models/features.pkl") -> list[str]:
    """Load the persisted feature list, falling back to the constant above."""
    path = Path(path)
    if path.exists():
        with open(path, "rb") as fh:
            return list(pickle.load(fh))
    return list(FEATURES)
