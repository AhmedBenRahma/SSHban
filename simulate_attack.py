import pandas as pd
import time
import pickle

# Charger tes propres features pour garantir la compatibilité
with open("features.pkl", "rb") as f:
    features = pickle.load(f)

colonnes = ['Src IP'] + features
fichier = "flow_en_direct.csv"

# Créer un fichier CSV tout neuf
pd.DataFrame(columns=colonnes).to_csv(fichier, index=False)
print("🎭 Simulateur Fis SecVision démarré...")

# 1. Trafic Normal
for i in range(3):
    ligne = {'Src IP': '192.168.1.50'}
    for feat in features: ligne[feat] = 1.0 # Petites valeurs = Normal
    pd.DataFrame([ligne]).to_csv(fichier, mode='a', header=False, index=False)
    print(f"✅ Flux normal {i+1}/3 envoyé")
    time.sleep(2)

# 2. Trafic d'Attaque
print("\n🚨 Lancement de l'attaque simulée depuis Kali (205.174.165.73)...")
for i in range(5):
    ligne = {'Src IP': '205.174.165.73'}
    for feat in features: ligne[feat] = 99999.0 # Valeurs extrêmes = Attaque
    pd.DataFrame([ligne]).to_csv(fichier, mode='a', header=False, index=False)
    print(f"🔥 Flux attaque {i+1}/5 envoyé")
    time.sleep(2)

print("\n✅ Simulation terminée — Vérifie Streamlit !")