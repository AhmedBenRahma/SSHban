import streamlit as st
import pandas as pd
import time
import os

# Configuration de la page
st.set_page_config(page_title="Fis SecVision - Live SOC", layout="wide")

# Rafraîchissement automatique toutes les 2 secondes
st.empty()
time.sleep(2)

st.title("🛡️ Fis SecVision : Détection SSH Brute Force Live")

# Section des alertes
st.header("🚨 Flux d'Alertes en Temps Réel")

if os.path.exists("alertes.csv"):
    try:
        alertes_df = pd.read_csv("alertes.csv", names=["Heure", "Type d'Attaque", "IP Source"])
        
        # 1. On vérifie que le tableau contient au moins une ligne
        if not alertes_df.empty:
            # Afficher la dernière alerte en gros et en rouge
            derniere_alerte = alertes_df.iloc[-1]
            st.error(f"⚠️ ATTAQUE DÉTECTÉE à {derniere_alerte['Heure']} | IP Suspecte : {derniere_alerte['IP Source']}")
            
            # Afficher le tableau complet (les 10 dernières alertes)
            st.dataframe(alertes_df.tail(10), use_container_width=True)
        else:
            # Le fichier existe mais il est vide
            st.success("✅ Aucun trafic suspect détecté pour le moment.")
            
    except pd.errors.EmptyDataError:
        st.success("✅ Aucun trafic suspect détecté pour le moment.")
else:
    st.success("✅ Aucun trafic suspect détecté pour le moment. Fichier d'alerte en attente.")

# Obliger Streamlit à relancer le script pour l'effet "Temps réel"
st.rerun()