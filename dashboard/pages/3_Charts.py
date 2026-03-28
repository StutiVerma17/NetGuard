# dashboard/pages/3_Charts.py
# Page 3 - Interactive Plotly charts
import sys, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit            as st
import plotly.express       as px
import plotly.graph_objects as go
import pandas               as pd
from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT, ".env"))

st.set_page_config(page_title="Charts | NetGuard", page_icon="📈", layout="wide")

BG   = "#0d0d1a"
PAP  = "#12122a"
GRID = "#1a1a3e"
FONT = "#e2e8f0"
SEV_C = {"Critical":"#e74c3c","High":"#e67e22",
          "Medium":"#f1c40f","Low":"#27ae60","Informational":"#2980b9"}

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background:#0d0d1a; color:#e2e8f0; }
[data-testid="stSidebar"] { background:#12122a; border-right:2px solid #4a1d96; }
[data-testid="stSidebar"] * { color:#c4b5fd !important; }
h1 { color:#a78bfa !important; } h3 { color:#a78bfa !important; }
</style>
""", unsafe_allow_html=True)

def _lay(fig, title="", h=380):
    fig.update_layout(
        title=dict(text=title, font=dict(color="#a78bfa", size=13)),
        paper_bgcolor=PAP, plot_bgcolor=GRID, font=dict(color=FONT),
        xaxis=dict(gridcolor=GRID, zerolinecolor=GRID, tickfont=dict(size=9)),
        yaxis=dict(gridcolor=GRID, zerolinecolor=GRID),
        legend=dict(bgcolor=PAP, bordercolor="#4a1d96", font=dict(size=10)),
        margin=dict(l=36,r=16,t=44,b=36), height=h,
    )
    return fig

st.markdown("""
<div style='background:linear-gradient(135deg,#1a1a3e,#2d1b69);
            border:1px solid #4a1d96;border-radius:14px;padding:22px 30px;margin-bottom:20px;'>
  <h1 style='margin:0;color:#a78bfa;'>📈 Charts &amp; Analytics</h1>
  <p style='margin:4px 0 0;color:#9ca3af;font-size:13px;'>
    Interactive Plotly visualisations - hover, zoom, click legend to toggle
  </p>
</div>
""", unsafe_allow_html=True)

df = st.session_state.get("scan_df")
if df is None or df.empty:
    st.info("No scan data yet. Run a scan from the **🏠 Overview** page.")
    st.stop()

sev_order = ["Critical","High","Medium","Low","Informational"]

# Row 1 - Severity donut + Ports per host
r1c1, r1c2 = st.columns(2)
with r1c1:
    counts = df["severity"].value_counts().reindex(sev_order).dropna()
    fig = go.Figure(go.Pie(
        labels=counts.index, values=counts.values, hole=0.55,
        marker=dict(colors=[SEV_C[s] for s in counts.index],
                    line=dict(color=BG, width=2)),
        textinfo="label+percent+value",
        textfont=dict(color=FONT, size=11),
    ))
    st.plotly_chart(_lay(fig, "Severity Distribution", 360), use_container_width=True)

with r1c2:
    pc = df.groupby("ip")["port"].count().reset_index()
    pc.columns = ["IP","Ports"]
    pc = pc.sort_values("Ports", ascending=False)
    fig = px.bar(pc, x="IP", y="Ports",
                 color="Ports",
                 color_continuous_scale=[[0,"#1a1a3e"],[0.5,"#7c3aed"],[1,"#fbbf24"]],
                 text="Ports")
    fig.update_traces(textposition="outside")
    st.plotly_chart(_lay(fig, "Open Ports per Host", 360), use_container_width=True)

# Row 2 - Risk heatmap + Scatter risk vs ports
r2c1, r2c2 = st.columns(2)
with r2c1:
    pivot = df.pivot_table(
        index="ip", columns="service",
        values="risk_score", aggfunc="max",
    ).fillna(0)
    fig = px.imshow(
        pivot, color_continuous_scale="RdYlGn_r",
        labels=dict(x="Service", y="Host", color="Risk"),
        aspect="auto",
    )
    st.plotly_chart(_lay(fig, "Host × Service Risk Heatmap", 360), use_container_width=True)

with r2c2:
    host_agg = df.groupby("ip").agg(
        ports   = ("port",       "count"),
        risk    = ("risk_score", "max"),
        sev     = ("severity",   lambda x: x.value_counts().index[0]),
        malicious=("malicious_reports","max"),
    ).reset_index()
    fig = px.scatter(
        host_agg, x="ports", y="risk",
        size="malicious",
        color="sev",
        color_discrete_map=SEV_C,
        text="ip",
        labels={"ports":"Open Ports","risk":"Max Risk Score","sev":"Severity"},
        size_max=40,
    )
    fig.update_traces(textposition="top center")
    st.plotly_chart(_lay(fig, "Risk Score vs Open Ports", 360), use_container_width=True)

# Row 3 - CVE/CVSS bar + VT stacked bar
r3c1, r3c2 = st.columns(2)
with r3c1:
    cvss = df[["service","cvss"]].drop_duplicates().sort_values("cvss", ascending=False).head(15)
    fig  = px.bar(cvss, x="cvss", y="service", orientation="h",
                  color="cvss",
                  color_continuous_scale=[[0,"#27ae60"],[0.5,"#f1c40f"],[1,"#e74c3c"]],
                  text="cvss")
    fig.update_traces(texttemplate="%{text:.1f}", textposition="outside")
    st.plotly_chart(_lay(fig, "CVSS Score by Service (Top 15)", 360), use_container_width=True)

with r3c2:
    vt = df.groupby("ip").agg(
        malicious  = ("malicious_reports", "max"),
        suspicious = ("suspicious_count",  "max"),
        harmless   = ("harmless_count",    "max"),
    ).reset_index()
    fig = go.Figure()
    for col, c, lbl in [
        ("malicious",  "#e74c3c", "Malicious"),
        ("suspicious", "#e67e22", "Suspicious"),
        ("harmless",   "#27ae60", "Harmless"),
    ]:
        fig.add_trace(go.Bar(x=vt["ip"], y=vt[col],
                             name=lbl, marker_color=c))
    fig.update_layout(barmode="stack")
    st.plotly_chart(_lay(fig, "VirusTotal Reports per Host", 360), use_container_width=True)
