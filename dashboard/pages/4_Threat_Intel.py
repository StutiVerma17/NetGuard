# dashboard/pages/4_Threat_Intel.py
# Page 4 - Threat Intelligence deep-dive
import sys, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st
import pandas    as pd
import plotly.graph_objects as go
import plotly.express       as px
from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT, ".env"))

st.set_page_config(page_title="Threat Intel | NetGuard", page_icon="🚨", layout="wide")
BG = "#0d0d1a"; PAP = "#12122a"; GRID = "#1a1a3e"; FONT = "#e2e8f0"
SEV_C = {"Critical":"#e74c3c","High":"#e67e22",
          "Medium":"#f1c40f","Low":"#27ae60","Informational":"#2980b9"}

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background:#0d0d1a; color:#e2e8f0; }
[data-testid="stSidebar"] { background:#12122a; border-right:2px solid #4a1d96; }
[data-testid="stSidebar"] * { color:#c4b5fd !important; }
h1, h2 { color:#a78bfa !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style='background:linear-gradient(135deg,#1a1a3e,#2d1b69);
            border:1px solid #4a1d96;border-radius:14px;padding:22px 30px;margin-bottom:20px;'>
  <h1 style='margin:0;color:#a78bfa;'>🚨 Threat Intelligence</h1>
  <p style='margin:4px 0 0;color:#9ca3af;font-size:13px;'>
    VirusTotal data, CVE references &amp; remediation actions
  </p>
</div>
""", unsafe_allow_html=True)

df = st.session_state.get("scan_df")
if df is None or df.empty:
    st.info("No scan data yet. Run a scan from the **🏠 Overview** page.")
    st.stop()

# Top critical findings
st.markdown("### 🔴 Critical & High Findings")
alert_df = df[df["severity"].isin(["Critical","High"])].sort_values("risk_score", ascending=False)
if alert_df.empty:
    st.success("✅ No Critical or High findings detected.")
else:
    cols = ["ip","port","service","vulnerability","severity",
            "risk_score","cve_ref","cvss","malicious_reports","country","action"]
    cols = [c for c in cols if c in alert_df.columns]
    st.dataframe(alert_df[cols], use_container_width=True, hide_index=True)
st.divider()

# CVE reference cards
st.markdown("### 📄 CVE & Vulnerability Reference")
cve_df = df[["service","vulnerability","cve_ref","cvss","action"]].drop_duplicates()
cve_df = cve_df.sort_values("cvss", ascending=False)
for _, row in cve_df.iterrows():
    cvss  = float(row.get("cvss", 0))
    color = ("#e74c3c" if cvss >= 9 else "#e67e22" if cvss >= 7
             else "#f1c40f" if cvss >= 4 else "#27ae60")
    with st.expander(f"[{row['cve_ref']}]  {row['vulnerability']}  -  CVSS {cvss}"):
        c1, c2 = st.columns([1, 3])
        c1.metric("CVSS Score", f"{cvss}/10")
        c2.markdown(f"**Service:** `{row['service']}`  \\ **CVE:** `{row['cve_ref']}`")
        st.info(f"🔧 **Action:** {row['action']}")
st.divider()

# Country map
if "country" in df.columns:
    st.markdown("### 🌍 Geographic Distribution")
    geo = df[df["country"] != "Unknown"].groupby("country").agg(
        count=("ip", "count"), max_risk=("risk_score","max")
    ).reset_index()
    if not geo.empty:
        fig = px.choropleth(
            geo, locations="country", locationmode="ISO-3",
            color="max_risk",
            hover_name="country",
            hover_data=["count","max_risk"],
            color_continuous_scale="RdYlGn_r",
            title="Max Risk Score by Country",
        )
        fig.update_layout(
            paper_bgcolor=PAP, plot_bgcolor=PAP,
            font=dict(color=FONT), height=420,
            geo=dict(bgcolor=BG, lakecolor=BG, landcolor="#1a1a3e",
                     showframe=False, showcoastlines=True,
                     coastlinecolor="#4a1d96"),
        )
        st.plotly_chart(fig, use_container_width=True)
