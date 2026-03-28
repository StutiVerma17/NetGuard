# dashboard/pages/5_History.py
# Page 5 - Scan history from SQLite database
import sys, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st
import pandas    as pd
import plotly.express as px
from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT, ".env"))

from modules.database import get_sessions, get_session_records, delete_session, get_db_stats

st.set_page_config(page_title="History | NetGuard", page_icon="🗂️", layout="wide")

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
  <h1 style='margin:0;color:#a78bfa;'>🗂️ Scan History</h1>
  <p style='margin:4px 0 0;color:#9ca3af;font-size:13px;'>
    All previous scan sessions stored in the local database
  </p>
</div>
""", unsafe_allow_html=True)

stats = get_db_stats()
m1,m2,m3,m4 = st.columns(4)
m1.metric("Total Sessions",  stats["total_sessions"])
m2.metric("Total Records",   stats["total_records"])
m3.metric("Critical Total",  stats["critical_total"])
m4.metric("High Total",      stats["high_total"])
st.divider()

sessions = get_sessions(limit=50)
if not sessions:
    st.info("No scan sessions found. Run a scan to create history.")
    st.stop()

sess_df = pd.DataFrame(sessions)
st.markdown("### 📋 Session List")
st.dataframe(sess_df, use_container_width=True, hide_index=True)
st.divider()

# Risk trend line
if len(sess_df) > 1:
    st.markdown("### 📈 Risk Trend")
    trend = sess_df[["started_at","max_risk","critical_ct","high_ct"]].copy()
    trend = trend.sort_values("started_at")
    fig = px.line(trend, x="started_at",
                  y=["max_risk","critical_ct","high_ct"],
                  markers=True,
                  labels={"value":"Count/Score","variable":"Metric","started_at":"Scan Time"},
                  color_discrete_map={
                      "max_risk":   "#e74c3c",
                      "critical_ct":"#f1c40f",
                      "high_ct":    "#e67e22",
                  })
    fig.update_layout(
        paper_bgcolor="#12122a", plot_bgcolor="#1a1a3e",
        font=dict(color="#e2e8f0"), height=340,
        xaxis=dict(gridcolor="#1a1a3e"), yaxis=dict(gridcolor="#1a1a3e"),
    )
    st.plotly_chart(fig, use_container_width=True)
    st.divider()

# View / delete session
st.markdown("### 🔍 View Session Details")
sel_id = st.selectbox("Select session:",
                       options=[s["id"] for s in sessions],
                       format_func=lambda i: next(
                           f"#{i} - {s['started_at']} - {s['targets']}"
                           for s in sessions if s["id"] == i
                       ))

c1, c2 = st.columns([3,1])
with c1:
    if st.button("📂 Load Session", use_container_width=True):
        recs = get_session_records(sel_id)
        if recs:
            st.dataframe(pd.DataFrame(recs), use_container_width=True, hide_index=True, height=400)
        else:
            st.warning("Session has no records.")
with c2:
    if st.button("🗑️ Delete Session", use_container_width=True):
        delete_session(sel_id)
        st.success(f"Session #{sel_id} deleted.")
        st.rerun()
