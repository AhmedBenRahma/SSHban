"""The simulator must emit a well-formed flow stream the analyzer can read."""
from pathlib import Path

import pandas as pd

from sshban.features import FEATURES
from sshban.simulate import ATTACKER_IP, run

ROOT = Path(__file__).resolve().parent.parent
FEATS = ROOT / "models" / "features.pkl"


def test_simulate_writes_expected_shape(tmp_path):
    flow = tmp_path / "flow.csv"
    run(flow_csv=flow, features_path=FEATS, benign=2, attack=3, delay=0)
    df = pd.read_csv(flow)
    assert len(df) == 5
    assert list(df.columns) == ["Src IP"] + FEATURES
    assert (df["Src IP"] == ATTACKER_IP).sum() == 3
