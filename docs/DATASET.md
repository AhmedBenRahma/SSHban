# Dataset — CICIDS2017

SSHban trains on **CICIDS2017**, a labelled intrusion-detection dataset from the
Canadian Institute for Cybersecurity (University of New Brunswick).

- **File used:** `Tuesday-WorkingHours.pcap_ISCX.csv` — it contains benign traffic
  and a real `SSH-Patator` SSH brute-force campaign.
- **Download:** <https://www.unb.ca/cic/datasets/ids-2017.html> (free, registration
  required). The CSV is large, so it is **not** committed to this repository
  (see `.gitignore`).

## Preparation

Handled automatically by `sshban/train.py`:

1. Strip whitespace from column names.
2. Keep only `BENIGN` and `SSH-Patator` rows.
3. Build the binary target (`SSH-Patator` = 1).
4. Replace infinities with `NaN` and drop rows missing any feature.
5. 80/20 stratified train/test split.

## Features (11)

Flow-behaviour features only — no packet contents, no login counters. See
`sshban/features.py` for the authoritative list and one-line descriptions.

| Feature | Meaning |
|---|---|
| `Init_Win_bytes_forward` | Initial TCP receive window advertised by the client (top signal) |
| `Average Packet Size` | Mean packet size over the flow |
| `act_data_pkt_fwd` | Forward packets that carried a payload |
| `Total Fwd/Backward Packets` | Packet counts in each direction |
| `Flow Duration` | Lifetime of the flow (µs) |
| `Flow Bytes/s`, `Flow Packets/s` | Throughput and packet rate |
| `Flow IAT Mean`, `Fwd IAT Mean` | Inter-arrival timing |
| `Avg Fwd Segment Size` | Mean forward TCP segment size |

## Reproduce

```bash
sshban train --data Tuesday-WorkingHours.pcap_ISCX.csv
```

Prints the held-out classification report and confusion matrix, and writes
`models/model.pkl` + `models/features.pkl`.
