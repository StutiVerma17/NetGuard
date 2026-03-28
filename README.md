# 🛡️ NetGuard - Cyber Risk Assessment & Threat Intelligence Platform

NetGuard is a Python-based network security assessment tool that automates
vulnerability discovery, threat intelligence enrichment, and risk reporting.

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.9+ | https://python.org |
| Nmap | 7.94+ | https://nmap.org/download.html |
| VirusTotal account | Free | https://www.virustotal.com/gui/join-us |
| Gmail account with 2FA | - | https://myaccount.google.com/security |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure credentials

Edit the `.env` file and fill in your values:

```env
VT_API_KEY=your_virustotal_api_key_here
GMAIL_SENDER=your_gmail@gmail.com
GMAIL_PASSWORD=xxxxxxxxxxxxxxxx
GMAIL_RECIPIENT=admin@yourdomain.com
SCAN_TARGETS=testphp.vulnweb.com,testasp.vulnweb.com
```

### 3. Gmail App Password setup

1. Enable 2-Step Verification: https://myaccount.google.com/security
2. Go to App Passwords: https://myaccount.google.com/apppasswords
3. Select **Mail** and generate a password
4. Copy the 16-character password (remove spaces) into `.env`

### 4. Run the dashboard

```bash
streamlit run dashboard/app.py
```

Open: http://localhost:8501

### 5. (Optional) Run from Jupyter Notebook

```bash
jupyter notebook main.ipynb
```

Run all cells in order to write all module files, then run the dashboard.

---

## Architecture

```
netguard/
├── modules/
│   ├── scanner.py       Nmap scanning + VirusTotal enrichment
│   ├── analyser.py      Risk scoring (CVSS-based)
│   ├── database.py      SQLite scan history
│   └── emailer.py       HTML email + PDF report
├── dashboard/
│   ├── app.py           Overview page (entry point)
│   └── pages/
│       ├── 2_Scan_Data.py
│       ├── 3_Charts.py
│       ├── 4_Threat_Intel.py
│       └── 5_History.py
├── main.ipynb
├── .env
├── .gitignore
├── requirements.txt
└── license.txt
```

---

## Recommended Test Targets

These are intentionally vulnerable or publicly accessible test targets:

| Target | Description |
|--------|-------------|
| `testphp.vulnweb.com` | Acunetix PHP test site - HTTP, FTP, MySQL exposed |
| `testasp.vulnweb.com` | Acunetix ASP test site - HTTP, SMTP open |
| `testaspnet.vulnweb.com` | Acunetix ASP.NET test site |
| `zero.webappsecurity.com` | HP Zero Bank - demo banking app |
| `pentest-ground.com` | Pentesting practice environment |
| `demo.testfire.net` | IBM Altoro Mutual - legacy demo bank |
| `demo.owasp-juice.shop` | OWASP Juice Shop - intentionally insecure app |
| `scanme.nmap.org` | Official Nmap scan-me target |

> ⚠️ **Only scan targets you own or have explicit written permission to scan.**
> Unauthorized scanning may violate computer misuse laws in your jurisdiction.

---

## Risk Scoring

Each finding is scored 1–10:

```
risk_score = min(10,  1  +  service_bonus  +  vt_malicious_count)
```

| Score | Severity | Action |
|-------|----------|--------|
| 9–10 | Critical | Remediate immediately |
| 7–8  | High     | Remediate within 24 hours |
| 4–6  | Medium   | Schedule remediation |
| 1–3  | Low      | Monitor |

---

## GitHub Repository Structure

Push the following to your GitHub repository:

```
netguard/
├── (all project files above)
├── docs/
│   ├── Project_Report.docx
│   ├── Agile_Documentation.docx
│   └── Presentation.pptx
├── assignments/          ← folder for previous assignments
│   └── (your previous assignment files)
└── license.txt
```

**Steps to push to GitHub:**
```bash
git init
git add .
git commit -m "Initial commit - NetGuard v1.0"
git remote add origin https://github.com/YOUR_USERNAME/netguard.git
git push -u origin main
```

---

## Troubleshooting

**Nmap not found**
```bash
# Windows (Chocolatey)
choco install nmap
# Linux
sudo apt-get install nmap
# macOS
brew install nmap
```

**Gmail authentication failed**
- Use an App Password, not your regular Gmail password
- Remove spaces from the App Password before pasting into `.env`
- Ensure 2FA is enabled first

**VT_API_KEY not working**
- Get a free key at https://www.virustotal.com/gui/my-apikey
- Free tier: 500 requests/day, 4 requests/minute

---

## License

MIT - see `license.txt`
