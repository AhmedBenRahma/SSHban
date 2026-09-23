"""Real-time SOC dashboard for the SSHban alert feed (cross-platform).

Reads the ``alerts.csv`` written by ``sshban detect`` and renders a live
security-operations console: status tiles, an attacks-per-minute chart, and the
running alert table. Runs anywhere Streamlit runs.

    streamlit run sshban/dashboards/live.py
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ALERTS_CSV = os.environ.get("SSHBAN_ALERTS", "alerts.csv")
BRAND = os.environ.get("SSHBAN_BRAND", "SSHban IDS")
REFRESH_SECONDS = 3

st.set_page_config(page_title=BRAND, page_icon="shield", layout="wide")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    [data-testid="stAppViewContainer"]{
        background-color:#04070a;
        background-image:linear-gradient(rgba(0,229,255,.05) 1px,transparent 1px),
                         linear-gradient(90deg,rgba(0,229,255,.05) 1px,transparent 1px);
        background-size:40px 40px; font-family:'Share Tech Mono',monospace;}
    h1,h2,h3{color:#00e5ff!important;text-shadow:0 0 10px rgba(0,229,255,.5);
        text-transform:uppercase;letter-spacing:1px;}
    [data-testid="stMetric"]{background:linear-gradient(180deg,rgba(0,20,10,.85),rgba(0,0,0,1));
        border:1px solid #00ff88;border-radius:4px;padding:14px;
        box-shadow:0 0 15px rgba(0,255,136,.08) inset;}
    [data-testid="stMetricValue"]{color:#00ff88!important;text-shadow:0 0 10px #00ff88;}
    [data-testid="stMetricLabel"]{color:#00e5ff!important;}
    .stAlert{background:rgba(25,0,10,.85)!important;border:1px solid #ff2e63!important;
        color:#ff2e63!important;box-shadow:0 0 20px rgba(255,46,99,.3);}
    #MainMenu,footer,header{visibility:hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<h1>&#128737; SSHban &mdash; Live SSH Intrusion Detection</h1>", unsafe_allow_html=True)
st.caption("Flow-behaviour detection of SSH brute-force attacks · alert feed from the live analyzer")


def load_alerts() -> pd.DataFrame:
    path = Path(ALERTS_CSV)
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame(columns=["Time", "Attack type", "Source IP"])
    try:
        return pd.read_csv(path, names=["Time", "Attack type", "Source IP"])
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=["Time", "Attack type", "Source IP"])


placeholder = st.empty()
with placeholder.container():
    alerts = load_alerts()
    total = len(alerts)
    attackers = alerts["Source IP"].nunique() if total else 0

    status = "SECURE"
    if total > 20:
        status = "CRITICAL"
    elif total > 0:
        status = "UNDER ATTACK"

    c1, c2, c3 = st.columns(3)
    c1.metric("ALERTS RAISED", f"{total}")
    c2.metric("DISTINCT SOURCE IPs", f"{attackers}")
    c3.metric("NETWORK STATUS", status)

    st.markdown("<br>", unsafe_allow_html=True)

    if total:
        st.error(f"BREACH ATTEMPT DETECTED — {total} malicious SSH flow(s) classified")
        left, right = st.columns([2, 1])
        with left:
            st.subheader("Alert feed")
            st.dataframe(alerts.tail(15).iloc[::-1], use_container_width=True, hide_index=True)
        with right:
            st.subheader("Attacks by source IP")
            counts = alerts["Source IP"].value_counts().reset_index()
            counts.columns = ["Source IP", "Flows"]
            fig = px.bar(counts, x="Flows", y="Source IP", orientation="h",
                         template="plotly_dark", color_discrete_sequence=["#ff2e63"])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              margin=dict(l=0, r=0, t=10, b=0), height=260)
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("SYSTEM CLEAR — no malicious SSH flows detected.")

# auto-refresh for the live effect
time.sleep(REFRESH_SECONDS)
st.rerun()
