# dashboard/app.py
# ------------------------------------------------------------------
# NetGuard - Main Dashboard (Overview page)
# Run: streamlit run dashboard/app.py
# ------------------------------------------------------------------
import sys, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st
import pandas    as pd
import plotly.express       as px
import plotly.graph_objects as go
from datetime import datetime
from dotenv   import load_dotenv

from modules.scanner  import run_full_pipeline, is_valid_target
from modules.database import init_db, save_scan, get_db_stats
from modules.emailer  import send_alert_email, build_pdf_report

load_dotenv(os.path.join(ROOT, ".env"))

# ── Page config ────────────────────────────────────────────────
st.set_page_config(
    page_title="NetGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
init_db()

# ── Credentials ────────────────────────────────────────────────
VT_API_KEY      = os.environ.get("VT_API_KEY",      "")
GMAIL_SENDER    = os.environ.get("GMAIL_SENDER",    "")
GMAIL_PASSWORD  = os.environ.get("GMAIL_PASSWORD",  "")
GMAIL_RECIPIENT = os.environ.get("GMAIL_RECIPIENT", "")
TARGETS_ENV     = os.environ.get("SCAN_TARGETS",    "")

DEFAULT_TARGETS = "testphp.vulnweb.com,testasp.vulnweb.com"
DEFAULT_LIST    = [t.strip() for t in (TARGETS_ENV or DEFAULT_TARGETS).split(",") if t.strip()]

vt_ok    = bool(VT_API_KEY and not VT_API_KEY.startswith("your_"))
email_ok = bool(GMAIL_SENDER and GMAIL_PASSWORD and GMAIL_RECIPIENT
                and not GMAIL_SENDER.startswith("your_"))

# ── Session state defaults ─────────────────────────────────────
for k, v in [("scan_df", None), ("scan_time", None),
             ("session_id", None), ("targets_used", None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── Global CSS ─────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background:#0d0d1a; color:#e2e8f0; }
[data-testid="stSidebar"]          { background:#12122a; border-right:2px solid #4a1d96; }
[data-testid="stSidebar"] *        { color:#c4b5fd !important; }
h1 { color:#a78bfa !important; }
h2 { color:#7c3aed !important; }
h3 { color:#6d28d9 !important; }
[data-testid="stMetric"] {
    background:linear-gradient(135deg,#1a1a3e,#2d1b69);
    border:1px solid #4a1d96; border-radius:14px; padding:14px;
}
[data-testid="stMetricValue"] { color:#fbbf24 !important; font-size:2rem !important; }
[data-testid="stMetricLabel"] { color:#a78bfa !important; font-size:0.8rem !important; }
.stButton>button {
    background:linear-gradient(135deg,#4a1d96,#7c3aed) !important;
    border:none !important; color:#fff !important;
    border-radius:10px; font-weight:700;
}
[data-testid="stDownloadButton"]>button {
    background:linear-gradient(135deg,#065f46,#059669) !important;
    border:none !important; color:#fff !important; border-radius:10px;
}
input, textarea {
    background:#1a1a3e !important; color:#e2e8f0 !important;
    border:1px solid #4a1d9688 !important; border-radius:8px;
}
hr { border-color:#4a1d9633 !important; }
::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-thumb { background:#4a1d96; border-radius:3px; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ NetGuard")
    st.markdown("*Cyber Risk Assessment Platform*")
    st.divider()

    # Credential status
    st.markdown("**⚙️ Status**")
    st.caption(f"{'✅' if vt_ok    else '❌'} VirusTotal API")
    st.caption(f"{'✅' if email_ok else '❌'} Email alerts")
    st.divider()

    # Target input
    st.markdown("**🎯 Scan Targets**")
    st.caption("One target per line, or comma-separated:")
    target_input = st.text_area(
        "Targets", label_visibility="collapsed",
        value="",
        placeholder="testphp.vulnweb.com\ntestasp.vulnweb.com\n192.168.1.1",
        height=100,
    )

    st.markdown("**Quick targets:**")
    QUICK = [
        "testphp.vulnweb.com",
        "testasp.vulnweb.com",
        "testaspnet.vulnweb.com",
        "zero.webappsecurity.com",
        "pentest-ground.com",
        "demo.testfire.net",
        "demo.owasp-juice.shop",
        "scanme.nmap.org",
    ]
    for t in QUICK:
        st.caption(f"  • `{t}`")
    st.caption("⚠️ Only scan authorised targets!")

    # Parse targets
    raw_targets = [
        t.strip()
        for part in (target_input or "").replace(",", "\n").splitlines()
        for t in [part.strip()] if t.strip()
    ]
    if raw_targets:
        invalid = [t for t in raw_targets if not is_valid_target(t)]
        if invalid:
            st.warning(f"Invalid target(s) skipped: {', '.join(invalid)}")
        active_targets = [t for t in raw_targets if is_valid_target(t)] or DEFAULT_LIST
    else:
        active_targets = DEFAULT_LIST

    st.divider()
    st.markdown("**🚀 Controls**")
    scan_btn    = st.button("🚀 Run Scan",        use_container_width=True, type="primary")
    refresh_btn = st.button("🔄 Refresh / Reset", use_container_width=True)

    if refresh_btn:
        for k in ("scan_df", "scan_time", "session_id", "targets_used"):
            st.session_state[k] = None
        st.rerun()

    st.divider()
    db = get_db_stats()
    st.markdown("**📊 Database**")
    st.caption(f"Sessions : {db['total_sessions']}")
    st.caption(f"Records  : {db['total_records']}")
    st.caption(f"Critical : {db['critical_total']}")

# ── Run scan ───────────────────────────────────────────────────
if scan_btn:
    if not vt_ok:
        st.error("❌ VT_API_KEY not set. Open .env, add your VirusTotal API key, restart.")
    else:
        bar    = st.progress(0)
        status = st.empty()

        def _cb(pct, msg):
            bar.progress(min(float(pct), 1.0))
            status.info(f"⏳ {msg}")

        rows = run_full_pipeline(active_targets, VT_API_KEY, _cb)
        bar.empty()

        if not rows:
            status.warning(
                "Nmap returned no open ports. "
                "Try: (1) run as Administrator  "
                "(2) check nmap --version in terminal  "
                "(3) confirm target is reachable."
            )
        else:
            df = pd.DataFrame(rows)
            st.session_state.scan_df      = df
            st.session_state.scan_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.targets_used = active_targets
            sid = save_scan(active_targets, rows)
            st.session_state.session_id   = sid
            status.success(
                f"✅ Scan complete - {len(df)} finding(s) across {df['ip'].nunique()} host(s) "
                f"| Session #{sid} saved"
            )

            # Auto-send email if High/Critical found and email is configured
            alert_df = df[df["severity"].isin(["High", "Critical"])]
            if not alert_df.empty and email_ok:
                with st.spinner("📧 Sending alert email …"):
                    res = send_alert_email(
                        GMAIL_SENDER, GMAIL_PASSWORD, GMAIL_RECIPIENT,
                        alert_df, st.session_state.scan_time, int(df["risk_score"].max())
                    )
                if res is True:
                    st.success(f"📧 Alert email + PDF sent to {GMAIL_RECIPIENT}")
                else:
                    st.warning(f"⚠️ Email failed: {res}")

# ── Hero header ────────────────────────────────────────────────
st.markdown("""
<div style='background:linear-gradient(135deg,#1a1a3e 0%,#2d1b69 60%,#1a1a3e 100%);
            border:1px solid #4a1d96;border-radius:16px;padding:28px 36px;margin-bottom:24px;'>
  <div style='display:flex;align-items:center;gap:16px;'>
    <span style='font-size:44px;'>🛡️</span>
    <div>
      <h1 style='margin:0;color:#a78bfa;font-size:2.2rem;font-weight:800;'>NetGuard</h1>
      <p style='margin:4px 0 0;color:#9ca3af;font-size:14px;'>
        Cyber Risk Assessment &amp; Threat Intelligence Platform
      </p>
    </div>
    <div style='margin-left:auto;'>
      <span style='background:#4a1d96;color:#c4b5fd;padding:6px 16px;
                   border-radius:20px;font-size:12px;font-weight:600;'>🏠 Overview</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Scan time strip
if st.session_state.scan_time:
    c1, c2 = st.columns([8, 1])
    c1.info(
        f"🕐 Last scan: {st.session_state.scan_time}  |  "
        f"Session #{st.session_state.session_id}  |  "
        f"Targets: {', '.join(st.session_state.targets_used or [])}"
    )
    if c2.button("🔄", help="Reset"):
        for k in ("scan_df", "scan_time", "session_id", "targets_used"):
            st.session_state[k] = None
        st.rerun()
else:
    st.info("👋 No scan run yet. Enter a target in the sidebar and click **Run Scan**.")

st.divider()

df = st.session_state.scan_df
BG, GRID, FONT = "#12122a", "#1a1a3e", "#e2e8f0"
SEV_C = {"Critical":"#e74c3c","High":"#e67e22","Medium":"#f1c40f",
          "Low":"#27ae60","Informational":"#2980b9"}

if df is None or df.empty:
    # Welcome cards
    st.markdown("""
    <div style='text-align:center;padding:60px 20px;'>
      <div style='font-size:64px;'>🛡️</div>
      <h2 style='color:#a78bfa;'>Welcome to NetGuard</h2>
      <p style='color:#9ca3af;max-width:500px;margin:0 auto 32px;font-size:15px;line-height:1.7;'>
        Enter a target in the sidebar and click <strong style='color:#a78bfa;'>Run Scan</strong>
        to begin. Results will appear here with full risk analysis.
      </p>
      <div style='display:flex;gap:20px;justify-content:center;flex-wrap:wrap;'>
        <div style='background:#1a1a3e;border:1px solid #4a1d96;
                    border-radius:12px;padding:20px 28px;'>
          <div style='font-size:28px;'>🔍</div>
          <div style='color:#a78bfa;font-weight:600;margin-top:8px;'>Port Scanning</div>
          <div style='color:#6b7280;font-size:12px;'>65+ ports via Nmap</div>
        </div>
        <div style='background:#1a1a3e;border:1px solid #4a1d96;
                    border-radius:12px;padding:20px 28px;'>
          <div style='font-size:28px;'>🌐</div>
          <div style='color:#a78bfa;font-weight:600;margin-top:8px;'>Threat Intel</div>
          <div style='color:#6b7280;font-size:12px;'>VirusTotal enrichment</div>
        </div>
        <div style='background:#1a1a3e;border:1px solid #4a1d96;
                    border-radius:12px;padding:20px 28px;'>
          <div style='font-size:28px;'>📊</div>
          <div style='color:#a78bfa;font-weight:600;margin-top:8px;'>Risk Scoring</div>
          <div style='color:#6b7280;font-size:12px;'>CVSS-based analysis</div>
        </div>
        <div style='background:#1a1a3e;border:1px solid #4a1d96;
                    border-radius:12px;padding:20px 28px;'>
          <div style='font-size:28px;'>📧</div>
          <div style='color:#a78bfa;font-weight:600;margin-top:8px;'>Auto Alerts</div>
          <div style='color:#6b7280;font-size:12px;'>Email + PDF reports</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

else:
    # ── KPI Metrics ────────────────────────────────────────────
    st.markdown("### 📊 Key Metrics")
    hc = len(df[df["severity"].isin(["High","Critical"])])
    m1,m2,m3,m4,m5,m6 = st.columns(6)
    m1.metric("🖥 Hosts",         df["ip"].nunique())
    m2.metric("🔓 Open Ports",    len(df))
    m3.metric("⚙️ Services",      df["service"].nunique())
    m4.metric("💀 Max Risk",      int(df["risk_score"].max()))
    m5.metric("🚨 High+Critical", hc)
    m6.metric("🦠 Max VT Hits",   int(df["malicious_reports"].max()))
    st.divider()

    # ── Quick charts ───────────────────────────────────────────
    st.markdown("### 🗺 Quick Overview")
    oc1, oc2, oc3 = st.columns(3)

    with oc1:
        sev_order = ["Critical","High","Medium","Low","Informational"]
        counts    = df["severity"].value_counts().reindex(sev_order).dropna()
        fig = go.Figure(go.Pie(
            labels=counts.index, values=counts.values, hole=0.55,
            marker=dict(colors=[SEV_C[s] for s in counts.index],
                        line=dict(color=BG, width=2)),
            textinfo="label+percent", textfont=dict(color=FONT, size=10),
        ))
        fig.update_layout(
            title=dict(text="Severity Split", font=dict(color="#a78bfa", size=12)),
            paper_bgcolor=BG, height=280, margin=dict(l=0,r=0,t=36,b=0),
            showlegend=False, font=dict(color=FONT),
        )
        st.plotly_chart(fig, use_container_width=True)

    with oc2:
        pc = df.groupby("ip")["port"].count().reset_index()
        pc.columns = ["IP", "Ports"]
        fig = px.bar(pc, x="IP", y="Ports", color="Ports",
                     color_continuous_scale=[[0,"#1a1a3e"],[0.5,"#7c3aed"],[1,"#fbbf24"]],
                     text="Ports")
        fig.update_traces(textposition="outside", marker_line_width=1)
        fig.update_layout(
            title=dict(text="Ports per Host", font=dict(color="#a78bfa", size=12)),
            paper_bgcolor=BG, plot_bgcolor=GRID, height=280,
            showlegend=False, font=dict(color=FONT),
            margin=dict(l=0,r=0,t=36,b=40),
            xaxis=dict(gridcolor=GRID, tickfont=dict(size=9)),
            yaxis=dict(gridcolor=GRID),
        )
        st.plotly_chart(fig, use_container_width=True)

    with oc3:
        rs = df.groupby("ip")["risk_score"].max().reset_index()
        rs.columns = ["IP","Max Risk"]
        bar_c = ["#e74c3c" if v>=9 else "#e67e22" if v>=7 else "#f1c40f" if v>=4 else "#27ae60"
                 for v in rs["Max Risk"]]
        fig = go.Figure(go.Bar(
            x=rs["IP"], y=rs["Max Risk"],
            marker_color=bar_c,
            text=rs["Max Risk"], textposition="outside",
        ))
        fig.update_layout(
            title=dict(text="Max Risk per Host", font=dict(color="#a78bfa", size=12)),
            paper_bgcolor=BG, plot_bgcolor=GRID, height=280,
            showlegend=False, font=dict(color=FONT),
            margin=dict(l=0,r=0,t=36,b=40),
            xaxis=dict(gridcolor=GRID, tickfont=dict(size=9)),
            yaxis=dict(gridcolor=GRID, range=[0,11]),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ── Host risk summary ──────────────────────────────────────
    st.markdown("### 📌 Host Risk Summary")
    summary = df.groupby("ip").agg(
        hostname       = ("hostname",          "first"),
        total_ports    = ("port",               "count"),
        services       = ("service",            lambda x: ", ".join(sorted(x.unique()))),
        malicious_score= ("malicious_reports",  "max"),
        max_risk       = ("risk_score",         "max"),
        severity       = ("severity",           lambda x: x.value_counts().index[0]),
    ).reset_index()
    summary.columns = ["IP","Hostname","Ports","Services","VT Malicious","Max Risk","Top Severity"]
    summary = summary.sort_values("Max Risk", ascending=False)
    st.dataframe(summary, use_container_width=True, hide_index=True)
    st.divider()

    # ── Quick actions ──────────────────────────────────────────
    st.markdown("### 📧 Quick Actions")
    alert_df = df[df["severity"].isin(["Critical","High"])]
    qa1, qa2, qa3 = st.columns(3)

    with qa1:
        if not email_ok:
            st.warning("Email not configured in .env")
        else:
            if st.button(f"📧 Send Alert Email ({len(alert_df)} findings)",
                         use_container_width=True, disabled=alert_df.empty):
                with st.spinner("Sending …"):
                    res = send_alert_email(
                        GMAIL_SENDER, GMAIL_PASSWORD, GMAIL_RECIPIENT,
                        alert_df if not alert_df.empty else df.head(5),
                        st.session_state.scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        int(df["risk_score"].max()),
                    )
                if res is True:
                    st.success(f"Sent to {GMAIL_RECIPIENT}")
                else:
                    st.error(f"Failed: {res}")

    with qa2:
        _ae  = alert_df if not alert_df.empty else df.head(5)
        _ts  = st.session_state.scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _pdf = build_pdf_report(_ae, _ts, int(df["risk_score"].max()))
        st.download_button("⬇️ Download PDF Report", data=_pdf,
                           file_name="NetGuard_Report.pdf", mime="application/pdf",
                           use_container_width=True)

    with qa3:
        st.download_button("⬇️ Download CSV (Full)",
                           data=df.to_csv(index=False).encode("utf-8"),
                           file_name="netguard_scan.csv", mime="text/csv",
                           use_container_width=True)
