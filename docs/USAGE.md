# Usage

## Install

```bash
pip install -r requirements.txt   # or: pip install -e .
```

The trained model ships in `models/`, so detection and the demo work out of the box.

## Commands

`sshban` exposes four subcommands (also runnable as `python -m sshban.<module>`):

| Command | What it does |
|---|---|
| `sshban train --data <csv>` | Train the Random Forest on CICIDS2017; writes `models/`. |
| `sshban detect --flow <csv>` | Poll a flow CSV, score new flows, append attacks to `alerts.csv`. |
| `sshban simulate` | Emit a demo flow stream (benign, then an attack burst). |
| `sshban dashboard` | Launch the live Streamlit SOC dashboard. |

## End-to-end demo (no VM needed)

Three terminals:

```bash
sshban simulate                        # terminal 1: generate flows
sshban detect --flow flow_en_direct.csv # terminal 2: score -> alerts.csv
sshban dashboard                        # terminal 3: live dashboard
```

The simulator's attack flows are built from the model's own decision regions, so
they are genuinely classified as attacks — the dashboard fills with real detections.

## Against real traffic

1. Install [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) and start it on
   your interface, writing flow records to `flow_en_direct.csv`.
2. Run `sshban detect --flow flow_en_direct.csv`.
3. Run `sshban dashboard`.

## Configuration

Environment variables read by the dashboard:

- `SSHBAN_ALERTS` — path to the alert feed (default `alerts.csv`).
- `SSHBAN_BRAND` — dashboard title (default `SSHban IDS`).

## Windows host view

On a Windows OpenSSH host:

```bash
streamlit run sshban/dashboards/windows_ssh.py
```

reads the `OpenSSH/Operational` event log and surfaces failed-login bursts.
