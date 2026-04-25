import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle

# ── 1. Chargement ──────────────────────────────────────────────
print("Chargement du dataset...")
df = pd.read_csv("Tuesday-WorkingHours.pcap_ISCX.csv", encoding='utf-8', low_memory=False)
df.columns = df.columns.str.strip()

# ── 2. Garder seulement BENIGN et SSH-Patator ──────────────────
df = df[df['Label'].isin(['BENIGN', 'SSH-Patator'])]
print(f"Lignes après filtrage : {len(df)}")

# ── 3. Créer la colonne cible ──────────────────────────────────
df['target'] = (df['Label'] == 'SSH-Patator').astype(int)

# ── 4. Features ───────────────────────────────────────────────
features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Init_Win_bytes_forward',
    'act_data_pkt_fwd',
    'Flow IAT Mean',
    'Fwd IAT Mean',
]

# ── 5. Nettoyer ────────────────────────────────────────────────
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna(subset=features)

X = df[features]
y = df['target']

# ── 6. Split train / test ──────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train : {len(X_train)} | Test : {len(X_test)}")

# ── 7. Entraîner Random Forest ─────────────────────────────────
print("\nEntraînement du modèle... (patience ~30 secondes)")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# ── 8. Évaluation ──────────────────────────────────────────────
y_pred = model.predict(X_test)
print("\n── Résultats ──────────────────────────────────")
print(classification_report(y_test, y_pred, target_names=['Normal', 'SSH-Patator']))
print("Matrice de confusion :")
print(confusion_matrix(y_test, y_pred))

# ── 9. Sauvegarder ────────────────────────────────────────────
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)
with open("features.pkl", "wb") as f:
    pickle.dump(features, f)

print("\nModèle sauvegardé : model.pkl")