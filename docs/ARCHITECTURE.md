# Architecture

![Architecture](architecture.png)

SSHban is two paths over one feature contract (`sshban/features.py`).

## Offline — training (`sshban/train.py`)

```
CICIDS2017 (Tuesday)  ->  filter BENIGN vs SSH-Patator  ->  11 flow features
                      ->  Random Forest (100 trees)      ->  model.pkl + features.pkl
```

The feature list is the single source of truth: the same module is imported by
training, detection and the simulator, so the three can never drift apart.

## Online — detection

```
live traffic --(CICFlowMeter)--> flow_en_direct.csv
        |
        v
  LiveAnalyzer.predict()  ->  attack? --yes--> Alert -> alerts.csv
        ^                                              |
     model.pkl                                         v
                                          Streamlit dashboard (live)
```

- **`detect.py`** — `LiveAnalyzer` loads the model once and scores batches of
  flows. The scoring logic (`predict`, `alerts_for`) is separated from the polling
  loop (`watch`) so it is unit-testable without files or timers.
- **`dashboards/live.py`** — reads `alerts.csv` and renders status tiles, an
  alert feed, and an attacks-by-source-IP chart, refreshing every few seconds.
- **`dashboards/windows_ssh.py`** — an independent host-side view that reads the
  Windows OpenSSH event log.

## Design choices

- **Flow behaviour, not login counters** — resilient to slow / distributed attacks.
- **One feature contract, imported everywhere** — no train/serve skew.
- **Model derived demo signatures** — `simulate.py` uses flows the model itself
  classifies as attacks, so the demo exercises the real classifier.
- **Testable core + CI** — the decision logic is covered by pytest and CI.
