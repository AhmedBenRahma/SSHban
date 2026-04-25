import streamlit as st
import subprocess
import pandas as pd
import io
import time
import plotly.express as px

# --- Configuration de la page ---
st.set_page_config(page_title="IDS SENTINEL | YAGAMI", page_icon="🕷️", layout="wide")

# --- LE DESIGN HACKER ULTIME (CSS Customisé) ---
st.markdown("""
    <style>
    /* Importation d'une police de Hacker (Share Tech Mono) */
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    
    /* Arrière-plan global avec effet de grille (Grid) */
    [data-testid="stAppViewContainer"] {
        background-color: #030303;
        background-image: 
            linear-gradient(rgba(0, 243, 255, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 243, 255, 0.05) 1px, transparent 1px);
        background-size: 40px 40px;
        font-family: 'Share Tech Mono', monospace;
    }

    /* Style des Titres (Effet Néon Cyan) */
    h1, h2, h3 {
        color: #00f3ff !important;
        text-shadow: 0 0 10px rgba(0, 243, 255, 0.6);
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* La Signature "Yagami" */
    .yagami-sig {
        text-align: right;
        color: #ff0055;
        font-size: 16px;
        text-shadow: 0 0 8px #ff0055;
        letter-spacing: 4px;
        margin-top: -40px;
        margin-bottom: 30px;
        border-bottom: 1px solid rgba(255, 0, 85, 0.3);
        padding-bottom: 5px;
    }

    /* Boîtes de statistiques (Vert Matrix & Cyan) */
    [data-testid="metric-container"] {
        background: linear-gradient(180deg, rgba(0,20,0,0.8) 0%, rgba(0,0,0,1) 100%);
        border: 1px solid #00ff41;
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.1) inset;
        border-radius: 2px;
        padding: 15px;
    }
    [data-testid="stMetricValue"] {
        color: #00ff41 !important;
        text-shadow: 0 0 10px #00ff41;
    }
    [data-testid="stMetricLabel"] {
        color: #00f3ff !important;
        font-size: 1.2rem;
    }

    /* Boîte d'Alerte Critique (Rouge Sang) */
    .stAlert {
        background-color: rgba(20, 0, 0, 0.8) !important;
        border-left: 4px solid #ff0055 !important;
        border-top: 1px solid #ff0055 !important;
        border-bottom: 1px solid #ff0055 !important;
        border-right: 1px solid #ff0055 !important;
        color: #ff0055 !important;
        box-shadow: 0 0 20px rgba(255, 0, 85, 0.3);
    }
    
    /* Masquer l'interface par défaut de Streamlit */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# --- Logique de récupération PowerShell ---
def get_ssh_logs():
    cmd = 'Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 300 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | ConvertTo-Csv -NoTypeInformation'
    result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
    if result.stdout.strip() == "":
        return pd.DataFrame()
    df = pd.read_csv(io.StringIO(result.stdout))
    
    # Correction appliquée pour le format de la date !
    df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], format='mixed')
    return df

# --- En-tête du Dashboard ---
st.markdown("<h1>👁️‍🗨️ NEURAL-SSH IDS</h1>", unsafe_allow_html=True)
st.markdown("<div class='yagami-sig'>// SYSTEM ENGINEERED BY YAGAMI</div>", unsafe_allow_html=True)

# --- Boucle Temps Réel ---
placeholder = st.empty()

with placeholder.container():
    df = get_ssh_logs()
    
    if not df.empty:
        df_failed = df[df['Message'].str.contains("Failed|invalid", case=False, na=False)]
        
        # --- SECTION 1 : Les Métriques ---
        m1, m2, m3 = st.columns(3)
        m1.metric("REQUÊTES TOTALES", len(df))
        m2.metric("INTRUSIONS BLOQUÉES", len(df_failed))
        
        risk_level = "SÉCURISÉ"
        if len(df_failed) > 20: risk_level = "CRITIQUE"
        elif len(df_failed) > 5: risk_level = "ALERTE"
        m3.metric("STATUT DU RÉSEAU", risk_level)

        st.markdown("<br>", unsafe_allow_html=True) # Espace

        # --- SECTION 2 : Graphique d'Analyse ---
        st.subheader("📡 Analyse Topologique (Attaques par minute)")
        if not df_failed.empty:
            df_failed['minute'] = df_failed['TimeCreated'].dt.floor('min')
            chart_data = df_failed.groupby('minute').size().reset_index(name='Frappes')
            fig = px.area(chart_data, x='minute', y='Frappes', 
                          template="plotly_dark", 
                          color_discrete_sequence=['#ff0055']) # Rouge néon pour le graphique
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=30, b=0)
            )
            # Correction appliquée pour la largeur !
            st.plotly_chart(fig, width='stretch')

        # --- SECTION 3 : Tableaux de contrôle ---
        c1, c2 = st.columns(2)
        
        with c1:
            st.subheader("🛑 LOGS DE BRUTE-FORCE")
            if not df_failed.empty:
                st.error(f"BREACH ATTEMPT DETECTED : {len(df_failed)} signatures suspectes.")
                st.dataframe(df_failed.head(15), width='stretch')
            else:
                st.success("SYSTÈME INTÈGRE : Aucune menace détectée.")

        with c2:
            st.subheader("🟩 TRAFIC GLOBAL (PORT 22)")
            st.dataframe(df.head(15), width='stretch')
            
    else:
        st.info("📡 EN ATTENTE D'INTERCEPTION DE PAQUETS...")

# --- Rafraîchissement ---
time.sleep(3)
st.rerun()