# 🛡️ SSH Brute Force Attack Detection Using AI

![Academic Project](https://img.shields.io/badge/Academic-Project-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-green?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red?style=for-the-badge&logo=streamlit)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-orange?style=for-the-badge&logo=scikit-learn)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

---

## 🇬🇧 English Description

A real-time SSH brute force attack detection system using a **Random Forest** machine learning model and a **Streamlit** interactive dashboard.  
The attacker is a **Kali Linux VM** (VMware NAT) targeting a **Windows 11** host running **OpenSSH**.  
The detection engine reads Windows SSH event logs, classifies network flows using the trained model, and raises live alerts on the dashboard.

### Key Features
- ✅ Machine learning-based classification (Random Forest, 100 estimators)
- ✅ Real-time flow analysis from live CSV feeds
- ✅ Streamlit dashboard with 3 tabs: *Dataset Analysis*, *Live Monitor*, *AI Model*
- ✅ Trained on the publicly available **CICIDS2017** dataset
- ✅ Near-perfect detection: **100% accuracy**, **99% SSH-Patator recall**

---

## 🇫🇷 Description en Français

Un système de détection d'attaques SSH par force brute en temps réel, basé sur un modèle de machine learning **Random Forest** et un tableau de bord interactif **Streamlit**.  
L'attaquant est une **VM Kali Linux** (VMware NAT) ciblant un hôte **Windows 11** exécutant **OpenSSH**.  
Le moteur de détection lit les journaux d'événements SSH Windows, classifie les flux réseau à l'aide du modèle entraîné, et déclenche des alertes en direct sur le tableau de bord.

### Caractéristiques Principales
- ✅ Classification par apprentissage automatique (Random Forest, 100 estimateurs)
- ✅ Analyse de flux en temps réel depuis des fichiers CSV live
- ✅ Tableau de bord Streamlit avec 3 onglets : *Analyse du Dataset*, *Moniteur Live*, *Modèle IA*
- ✅ Entraîné sur le dataset public **CICIDS2017**
- ✅ Détection quasi-parfaite : **100% de précision**, **99% de rappel SSH-Patator**

---

## 🏗️ Architecture

```
┌──────────────────────┐        SSH Brute Force
│  Kali Linux VM       │ ──────────────────────►  ┌─────────────────────┐
│  (VMware NAT)        │                           │  Windows 11 Host    │
│  Attacker            │                           │  (OpenSSH Server)   │
└──────────────────────┘                           └────────┬────────────┘
                                                            │ Event Logs / Flow CSV
                                                            ▼
                                                   ┌─────────────────────┐
                                                   │  Python Analyzer    │
                                                   │  (live_analyzer.py) │
                                                   │  Random Forest      │
                                                   └────────┬────────────┘
                                                            │ Alerts
                                                            ▼
                                                   ┌─────────────────────┐
                                                   │  Streamlit Dashboard│
                                                   │  (dashboard.py)     │
                                                   └─────────────────────┘
```

---

## 📁 Repository Structure

```
ssh-bruteforce-detection/
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   └── .gitkeep          # Dataset too large to upload — see Dataset section
├── models/
│   └── .gitkeep          # model.pkl generated after training
├── src/
│   ├── model.py          # Train and save the Random Forest model
│   ├── dashboard.py      # Streamlit dashboard (3 tabs)
│   ├── live_analyzer.py  # Real-time flow analysis and alerting
│   └── simulate_attack.py# Demo: simulate a brute-force flow
├── utils/
│   ├── check_columns.py  # Inspect dataset columns
│   └── test.py           # Quick label distribution check
└── docs/
    └── architecture.png  # Architecture diagram
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/AhmedBenRahma/SSHban.git
cd SSHban

# Install dependencies
pip install -r requirements.txt
```

---

## 📋 Usage (Step by Step)

### 1. Download the Dataset
Download **Tuesday-WorkingHours.pcap_ISCX.csv** from the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) and place it in the `data/` folder.

### 2. Train the Model
```bash
python src/model.py
```
This produces `models/model.pkl` and `models/features.pkl`.

### 3. Launch the Dashboard
```bash
streamlit run src/dashboard.py
```
Open your browser at `http://localhost:8501`.

### 4. Launch the Live Analyzer
```bash
python src/live_analyzer.py
```
The analyzer watches `flow_en_direct.csv` and writes alerts to `alertes.csv`.

### 5. Simulate an Attack (Demo)
```bash
python src/simulate_attack.py
```
This appends a synthetic SSH-Patator flow to `flow_en_direct.csv` so you can observe detection in real time.

---

## 📊 Model Performance

| Metric                        | Value         |
|-------------------------------|---------------|
| Algorithm                     | Random Forest |
| Number of Estimators          | 100           |
| Accuracy                      | **100%**      |
| Recall (SSH-Patator)          | **99%**       |
| False Positives               | 2 / 86 363    |
| True Negatives (BENIGN)       | 86 361        |
| True Positives (SSH-Patator)  | 1 173         |
| False Negatives               | 6             |

### Confusion Matrix

```
                  Predicted BENIGN    Predicted SSH-Patator
Actual BENIGN          86 361                  2
Actual SSH-Patator          6               1 173
```

### Features Used (11)
1. Flow Duration
2. Total Fwd Packets
3. Total Backward Packets
4. Flow Bytes/s
5. Flow Packets/s
6. Average Packet Size
7. Avg Fwd Segment Size
8. Init_Win_bytes_forward
9. act_data_pkt_fwd
10. Flow IAT Mean
11. Fwd IAT Mean

---

## 📂 Dataset

**CICIDS2017 — Tuesday Working Hours**  
File: `Tuesday-WorkingHours.pcap_ISCX.csv`

| Class        | Samples    |
|--------------|-----------|
| BENIGN       | 432 074   |
| SSH-Patator  | 5 897     |

> **Citation:** Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018).  
> *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.*  
> In Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), pp. 108-116.  
> [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

---

## 🖼️ Screenshots

> _Screenshots of the Streamlit dashboard will be added here._

| Tab | Preview |
|-----|---------|
| Dataset Analysis | _(coming soon)_ |
| Live Monitor     | _(coming soon)_ |
| AI Model         | _(coming soon)_ |

---

## 🏷️ Topics / Tags

`cybersecurity` `machine-learning` `ssh` `brute-force` `intrusion-detection` `streamlit` `random-forest` `CICIDS2017` `academic-project`

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ahmed Ben Rahma**  
Academic cybersecurity project — AI-based SSH intrusion detection.
