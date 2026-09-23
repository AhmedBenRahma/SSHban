"""Detection logic tests, using the shipped model and sample flows."""
from pathlib import Path

import pandas as pd
import pytest

from sshban.detect import Alert, LiveAnalyzer
from sshban.features import FEATURES

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "models" / "model.pkl"
FEATS = ROOT / "models" / "features.pkl"


def _analyzer():
    return LiveAnalyzer(MODEL, FEATS)


def test_alert_csv_format():
    line = Alert("12:00:00", "SSH Brute Force", "205.174.165.73").to_csv_line()
    assert line == "12:00:00,SSH Brute Force,205.174.165.73\n"


def test_predict_returns_one_label_per_flow():
    an = _analyzer()
    df = pd.DataFrame([{**{f: 1.0 for f in FEATURES}} for _ in range(4)])
    preds = an.predict(df)
    assert len(preds) == 4
    assert set(preds) <= {0, 1}


def test_attack_signature_is_flagged():
    from sshban.simulate import ATTACK_FLOW
    an = _analyzer()
    df = pd.DataFrame([{"Src IP": "205.174.165.73", **ATTACK_FLOW}])
    alerts = an.alerts_for(df)
    assert len(alerts) == 1
    assert alerts[0].src_ip == "205.174.165.73"
    assert alerts[0].attack_type == "SSH Brute Force"


def test_benign_session_is_not_flagged():
    from sshban.simulate import BENIGN_FLOW
    an = _analyzer()
    df = pd.DataFrame([{"Src IP": "192.168.1.50", **BENIGN_FLOW}])
    assert an.alerts_for(df) == []


def test_missing_features_raise():
    an = _analyzer()
    with pytest.raises(KeyError):
        an.predict(pd.DataFrame([{"Flow Duration": 1.0}]))
