"""Windows-only dashboard: read the OpenSSH event log directly.

On a Windows host running OpenSSH Server, this reads the ``OpenSSH/Operational``
event log via PowerShell and surfaces failed-login bursts — a host-side view that
complements the network-flow detector. Requires Windows + PowerShell; it is a
convenience view, not the core detector.

    streamlit run sshban/dashboards/windows_ssh.py
"""
from __future__ import annotations

import io
import subprocess
import time

import pandas as pd
import plotly.express as px
import streamlit as st

BRAND = "SSHban — Host View (OpenSSH log)"
st.set_page_config(page_title=BRAND, page_icon="shield", layout="wide")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    [data-testid="stAppViewContainer"]{background-color:#04070a;font-family:'Share Tech Mono',monospace;
        background-image:linear-gradient(rgba(0,229,255,.05) 1px,transparent 1px),
                         linear-gradient(90deg,rgba(0,229,255,.05) 1px,transparent 1px);background-size:40px 40px;}
    h1,h2,h3{color:#00e5ff!important;text-shadow:0 0 10px rgba(0,229,255,.5);text-transform:uppercase;}
    [data-testid="stMetricValue"]{color:#00ff88!important;text-shadow:0 0 10px #00ff88;}
    #MainMenu,footer,header{visibility:hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)


def get_ssh_logs() -> pd.DataFrame:
    cmd = ('Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 300 '
           '-ErrorAction SilentlyContinue | Select-Object TimeCreated, Message '
           '| ConvertTo-Csv -NoTypeInformation')
    result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
    if not result.stdout.strip():
        return pd.DataFrame()
    df = pd.read_csv(io.StringIO(result.stdout))
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], format="mixed")
    return df


st.markdown("<h1>&#128065; SSHban — Host View</h1>", unsafe_allow_html=True)

df = get_ssh_logs()
if df.empty:
    st.info("Waiting for OpenSSH events… (Windows host with OpenSSH Server required)")
else:
    failed = df[df["Message"].str.contains("Failed|invalid", case=False, na=False)]
    m1, m2, m3 = st.columns(3)
    m1.metric("TOTAL EVENTS", len(df))
    m2.metric("FAILED LOGINS", len(failed))
    status = "SECURE"
    if len(failed) > 20:
        status = "CRITICAL"
    elif len(failed) > 5:
        status = "ALERT"
    m3.metric("HOST STATUS", status)

    if not failed.empty:
        st.subheader("Failed logins per minute")
        failed = failed.copy()
        failed["minute"] = failed["TimeCreated"].dt.floor("min")
        chart = failed.groupby("minute").size().reset_index(name="Attempts")
        fig = px.area(chart, x="minute", y="Attempts", template="plotly_dark",
                      color_discrete_sequence=["#ff2e63"])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
        st.subheader("Brute-force log")
        st.dataframe(failed.head(15), use_container_width=True)

time.sleep(3)
st.rerun()
