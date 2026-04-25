import pandas as pd
import pickle
import time
import os
from datetime import datetime

# 1. Charger le modèle et les features
with open("model.pkl", "rb") as f:
    model = pickle.load(f)
with open("features.pkl", "rb") as f:
    features = pickle.load(f)

print("🚀 Analyseur Live démarré. En attente de trafic...")

fichier_live = "flow_en_direct.csv"
lignes_lues = 0

while True:
    if os.path.exists(fichier_live):
        try:
            # Lire le fichier CSV généré par cicflowmeter
            df = pd.read_csv(fichier_live)
            
            # Si de nouvelles lignes ont été ajoutées
            if len(df) > lignes_lues:
                nouvelles_lignes = df.iloc[lignes_lues:]
                lignes_lues = len(df)
                
                # Nettoyer les colonnes pour correspondre aux features
                nouvelles_lignes.columns = nouvelles_lignes.columns.str.strip()
                
                # S'assurer que toutes les features requises sont là
                if all(feat in nouvelles_lignes.columns for feat in features):
                    X_live = nouvelles_lignes[features].fillna(0) # Gérer les valeurs vides
                    
                    # Faire la prédiction
                    predictions = model.predict(X_live)
                    
                    # Vérifier s'il y a une attaque (1 = SSH-Patator dans ton modèle)
                    for i, pred in enumerate(predictions):
                        if pred == 1:
                            ip_source = df.iloc[lignes_lues - len(nouvelles_lignes) + i].get('Src IP', 'Inconnue')
                            heure = datetime.now().strftime("%H:%M:%S")
                            alerte = f"{heure},SSH Brute Force,{ip_source}\n"
                            
                            print(f"🚨 ALERTE : Attaque détectée depuis {ip_source} !")
                            
                            # Écrire l'alerte dans un fichier pour Streamlit
                            with open("alertes.csv", "a") as f_alerte:
                                f_alerte.write(alerte)
        except Exception as e:
            pass # Ignorer les erreurs de lecture si le fichier est en cours d'écriture
            
    time.sleep(2) # Vérifier toutes les 2 secondes