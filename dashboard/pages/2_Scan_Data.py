# dashboard/pages/2_Scan_Data.py
# Page 2 - Full colour-coded scan results with filters
import sys, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st
import pandas    as pd
from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT, ".env"))

st.set_page_config(page_title="Scan Data | NetGuard", page_icon="📋", layout="wide")

SEV_C = {"Critical":"#e74c3c","High":"#e67e22",
          "Medium":"#f1c40f","Low":"#27ae60","Informational":"#2980b9"}

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background:#0d0d1a; color:#e2e8f0; }
[data-testid="stSidebar"] { background:#12122a; border-right:2px solid #4a1d96; }
[data-testid="stSidebar"] * { color:#c4b5fd !important; }
h1 { color:#a78bfa !important; }
[data-testid="stMetric"] { background:linear-gradient(135deg,#1a1a3e,#2d1b69);
    border:1px solid #4a1d96; border-radius:14px; padding:14px; }
[data-testid="stMetricValue"] { color:#fbbf24 !important; }
[data-testid="stMetricLabel"] { color:#a78bfa !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style='background:linear-gradient(135deg,#1a1a3e,#2d1b69);
            border:1px solid #4a1d96;border-radius:14px;padding:22px 30px;margin-bottom:20px;'>
  <h1 style='margin:0;color:#a78bfa;'>📋 Scan Data</h1>
  <p style='margin:4px 0 0;color:#9ca3af;font-size:13px;'>
    Full colour-coded results with filters
  </p>
</div>
""", unsafe_allow_html=True)

df = st.session_state.get("scan_df")
if df is None or df.empty:
    st.info("No scan data yet. Run a scan from the **🏠 Overview** page.")
    st.stop()

# Sidebar filters
with st.sidebar:
    st.markdown("**🔍 Filters**")
    sel_ip  = st.selectbox("IP",      ["All"] + sorted(df["ip"].unique().tolist()))
    sel_svc = st.selectbox("Service", ["All"] + sorted(df["service"].unique().tolist()))
    sel_sev = st.multiselect(
        "Severity",
        ["Critical","High","Medium","Low","Informational"],
        default=["Critical","High","Medium","Low","Informational"]
    )
    mn = int(df["risk_score"].min()); mx = int(df["risk_score"].max())
    if mn == mx: mx = mn + 1
    min_risk = st.slider("Min Risk Score", mn, mx, mn)
    search   = st.text_input("🔎 Search", "")

filt = df.copy()
if sel_ip  != "All": filt = filt[filt["ip"]      == sel_ip]
if sel_svc != "All": filt = filt[filt["service"] == sel_svc]
if sel_sev:          filt = filt[filt["severity"].isin(sel_sev)]
filt = filt[filt["risk_score"] >= min_risk]
if search.strip():
    mask = filt.apply(lambda r: search.lower() in str(r).lower(), axis=1)
    filt = filt[mask]

c1,c2,c3,c4 = st.columns(4)
c1.metric("Showing",      f"{len(filt)} / {len(df)}")
c2.metric("Hosts",        filt["ip"].nunique())
c3.metric("Critical+High",len(filt[filt["severity"].isin(["Critical","High"])]))
c4.metric("Avg Risk",     round(filt["risk_score"].mean(), 1) if not filt.empty else 0)
st.divider()

cols = ["ip","hostname","port","service","product","version",
        "risk_score","severity","vulnerability","cve_ref","cvss",
        "malicious_reports","country","action"]
cols = [c for c in cols if c in filt.columns]

def _color_sev(val):
    c = SEV_C.get(str(val), "")
    return f"background-color:{c}33;color:{c};font-weight:bold;" if c else ""

def _color_risk(val):
    try:
        v = float(val)
        c = "#e74c3c" if v>=9 else "#e67e22" if v>=7 else "#f1c40f" if v>=4 else "#27ae60"
        return f"color:{c};font-weight:bold;"
    except:
        return ""

styled = filt[cols].style
if "severity"   in cols: styled = styled.map(_color_sev,  subset=["severity"])
if "risk_score" in cols: styled = styled.map(_color_risk, subset=["risk_score"])

st.dataframe(styled, use_container_width=True, hide_index=True, height=480)
