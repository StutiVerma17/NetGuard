# modules/emailer.py - Email & PDF Report Module
import smtplib, logging, re, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from fpdf import FPDF

logger = logging.getLogger(__name__)
os.makedirs("reports", exist_ok=True)

SEV_COLORS = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f39c12", "Low": "#27ae60"}

def is_valid_email(addr: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr.strip()))

def build_html_email(alert_df, scan_time: str, max_risk: int) -> str:
    crit_n = int((alert_df["severity"] == "Critical").sum())
    max_sev = "Critical" if crit_n > 0 else "High"
    hosts = ", ".join(sorted(alert_df["ip"].unique()))
    sc = SEV_COLORS.get(max_sev, "#c0392b")
    rows_html = ""
    for _, row in alert_df.iterrows():
        sev = row.get("severity", "Low")
        color = SEV_COLORS.get(sev, "#888")
        rows_html += f"<tr><td>{row['ip']}</td><td>{row.get('vulnerability','')}</td><td style='color:{color};font-weight:bold;'>{sev}</td></tr>"
    return f"<html><body style='font-family:Arial;'><h2>NetGuard Alert</h2><p>Findings: {len(alert_df)}, Risk: {max_risk}/10, Time: {scan_time}</p><table border='1'><tr><th>IP</th><th>Vulnerability</th><th>Severity</th></tr>{rows_html}</table></body></html>"

def build_pdf_report(alert_df, scan_time: str, max_risk: int) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "NetGuard Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 10, f"Time: {scan_time} | Count: {len(alert_df)} | Max: {max_risk}", ln=True)
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 8, "IP"), pdf.cell(35, 8, "Vulnerability"), pdf.cell(20, 8, "Severity"), pdf.ln()
    pdf.set_font("Helvetica", "", 8)
    for _, row in alert_df.iterrows():
        ip = str(row.get("ip", ""))[:20]
        vuln = str(row.get("vulnerability", ""))[:20]
        sev = str(row.get("severity", ""))[:10]
        pdf.cell(40, 7, ip), pdf.cell(35, 7, vuln), pdf.cell(20, 7, sev), pdf.ln()
    return pdf.output(dest='S').encode('latin-1')

def send_alert_email(sender: str, password: str, recipient: str, alert_df, scan_time: str, max_risk: int):
    if not is_valid_email(sender) or not is_valid_email(recipient):
        return "Invalid email"
    subject = f"NetGuard - {len(alert_df)} findings"
    msg = MIMEMultipart("mixed")
    msg["From"], msg["To"], msg["Subject"] = sender, recipient, subject
    msg.attach(MIMEText(build_html_email(alert_df, scan_time, max_risk), "html"))
    pdf_bytes = build_pdf_report(alert_df, scan_time, max_risk)
    part = MIMEBase("application", "octet-stream")
    part.set_payload(pdf_bytes)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment; filename=Report.pdf")
    msg.attach(part)
    try:
        srv = smtplib.SMTP("smtp.gmail.com", 587)
        srv.starttls(), srv.login(sender, password), srv.send_message(msg), srv.quit()
        return True
    except:
        return "Failed"
