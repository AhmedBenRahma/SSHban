"""SSHban — network-flow SSH brute-force detection.

A behavioural intrusion detector: it classifies the *shape* of a network flow
(duration, packet counts, byte rates, inter-arrival timing) instead of counting
failed logins, so it catches slow / distributed SSH brute-force attacks that a
threshold-based tool like fail2ban never trips.
"""
from .features import FEATURES, load_features

__version__ = "1.0.0"
__all__ = ["FEATURES", "load_features", "__version__"]
