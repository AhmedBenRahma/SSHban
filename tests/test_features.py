"""The feature contract must stay stable and match the persisted model."""
import pickle
from pathlib import Path

from sshban.features import FEATURES, FEATURE_DESCRIPTIONS, load_features

ROOT = Path(__file__).resolve().parent.parent


def test_feature_list_is_stable():
    assert len(FEATURES) == 11
    assert len(set(FEATURES)) == len(FEATURES)  # no duplicates


def test_every_feature_is_documented():
    for f in FEATURES:
        assert f in FEATURE_DESCRIPTIONS


def test_persisted_features_match_constant():
    persisted = pickle.load(open(ROOT / "models" / "features.pkl", "rb"))
    assert list(persisted) == FEATURES


def test_load_features_fallback(tmp_path):
    # missing file -> falls back to the constant
    assert load_features(tmp_path / "nope.pkl") == FEATURES
