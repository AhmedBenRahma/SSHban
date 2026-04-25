# 🛡️ SSH Brute Force Attack Detection Using AI

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-RandomForest-orange)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red)
![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017-green)
![Accuracy](https://img.shields.io/badge/Accuracy-100%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **Academic Cybersecurity Project** — Real-time detection of SSH brute force attacks using Machine Learning (Random Forest) with a live Streamlit dashboard.

---

## 📋 Description

This project detects **SSH brute force attacks** in real time using a **Random Forest** classifier trained on the **CICIDS2017** dataset. When an attacker (Kali Linux VM) launches a brute force attack via Hydra against a Windows 11 host, the system automatically detects it and displays a live alert on the dashboard.

### Architecture

```
Kali Linux (VMware NAT)
        |
        |  SSH Brute Force (Hydra)
        ▼
Windows 11 Host (OpenSSH enabled)
        |
        |  Event Logs / Network Flows
        ▼
live_analyzer.py  ──►  Random Forest Model (99% recall)
        |
        |  alertes.csv
        ▼
Streamlit Dashboard (localhost:8501)
        |
        ▼
  🚨 LIVE ALERT DISPLAYED
```

---

## 📊 Dataset

- **Source:** [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — Canadian Institute for Cybersecurity
- **File used:** `Tuesday-WorkingHours.pcap_ISCX.csv`
- **Citation:** Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"*, ICISSP 2018.

| Label | Count |
|-------|-------|
| BENIGN | 432,074 |
| SSH-Patator | 5,897 |
| FTP-Patator | 7,938 |

---

## 🤖 Model Performance

| Metric | Normal | SSH-Patator |
|--------|--------|-------------|
| Precision | 100% | 100% |
| Recall | 100% | 99% |
| F1-Score | 100% | 100% |
| **Global Accuracy** | **100%** | |

**Confusion Matrix:**
```
[[86361    2]
 [    6 1173]]
```

**Features used (11):**
- Flow Duration
- Total Fwd Packets
- Total Backward Packets
- Flow Bytes/s
- Flow Packets/s
- Average Packet Size
- Avg Fwd Segment Size
- Init_Win_bytes_forward
- act_data_pkt_fwd
- Flow IAT Mean
- Fwd IAT Mean

---

## 🗂️ Project Structure

```
ssh-bruteforce-detection/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── model.py            # Train & save the Random Forest model
│   ├── dashboard.py        # Streamlit dashboard (3 tabs)
│   ├── live_analyzer.py    # Real-time flow analyzer
│   └── simulate_attack.py  # Attack simulator for demo
├── utils/
│   ├── check_columns.py    # Inspect dataset columns
│   └── test.py             # Quick label check
├── models/
│   └── .gitkeep            # model.pkl generated here after training
└── data/
    └── .gitkeep            # Place CICIDS2017 CSV here
```

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ssh-bruteforce-detection.git
cd ssh-bruteforce-detection

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Step 1 — Download the dataset
Download `Tuesday-WorkingHours.pcap_ISCX.csv` from [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and place it in the `data/` folder.

### Step 2 — Train the model
```bash
python src/model.py
```
This generates `model.pkl` and `features.pkl` in the `models/` folder.

### Step 3 — Launch the dashboard
```bash
streamlit run src/dashboard.py
```
Open your browser at `http://localhost:8501`

### Step 4 — Launch the live analyzer
```bash
# In a separate terminal
python src/live_analyzer.py
```

### Step 5 — Simulate or launch a real attack

**Option A — Simulation (no Kali needed):**
```bash
python src/simulate_attack.py
```

**Option B — Real attack from Kali Linux:**
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt ssh://WINDOWS_IP
```

### Step 6 — Watch the alert appear on the dashboard 🚨

---

## 🖥️ Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux (VMware NAT) |
| Victim | Windows 11 (OpenSSH enabled) |
| Detection | Python 3.x on Windows 11 |
| Dashboard | Streamlit — localhost:8501 |

---

## 🛠️ Tech Stack

- **Python 3.x**
- **pandas** — data manipulation
- **scikit-learn** — Random Forest model
- **streamlit** — live dashboard
- **matplotlib / seaborn** — visualizations
- **numpy** — numerical processing

---

## 📁 requirements.txt

```
pandas
numpy
scikit-learn
streamlit
matplotlib
seaborn
```

---

## 🔒 .gitignore

```
*.csv
*.pkl
*.pcap
__pycache__/
.streamlit/
*.pyc
alertes.csv
flow_en_direct.csv
```

---

## 👨‍🎓 Academic Context

This project was developed as part of an academic **Cybersecurity** course. It demonstrates:
- Real-world dataset usage (CICIDS2017)
- Supervised machine learning for intrusion detection
- Real-time monitoring with a professional dashboard
- Attack simulation in an isolated virtual environment

---

## 📄 License

MIT License — feel free to use and adapt for educational purposes.

---

## 🙏 References

- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [Scikit-learn Documentation](https://scikit-learn.org)
- [Streamlit Documentation](https://docs.streamlit.io)
