# modules/scanner.py
# ------------------------------------------------------------------
# Vulnerability Scanning Engine
#   - Nmap port/service detection (65+ ports)
#   - VirusTotal threat intelligence enrichment
#   - CVSS-inspired risk scoring
# ------------------------------------------------------------------
import subprocess
import xml.etree.ElementTree as ET
import time
import os
import re
import requests
import logging

logger = logging.getLogger(__name__)

# Ports to scan - covers most common attack surfaces
SCAN_PORTS = (
    "21,22,23,25,53,67,69,79,80,88,110,111,119,123,135,"
    "137,138,139,143,161,194,389,443,445,500,514,515,587,"
    "631,636,873,993,995,1080,1194,1433,1521,1723,2049,"
    "2375,2376,3306,3389,4444,5432,5900,5985,5986,6379,"
    "6443,6667,7001,8080,8443,8888,9042,9200,9300,9418,"
    "11211,27017,27018,50070,6000,548"
)

SCAN_DIR = "scan_results"
os.makedirs(SCAN_DIR, exist_ok=True)

# ------------------------------------------------------------------
# Vulnerability database
# Each service has: bonus score, display name, CVE ref, CVSS, action
# ------------------------------------------------------------------
VULN_DB = {
    "ftp":           {"bonus":3, "name":"Cleartext FTP",               "cve":"CVE-1999-0497",    "cvss":7.5,  "action":"Disable FTP; use SFTP or FTPS."},
    "telnet":        {"bonus":4, "name":"Cleartext Telnet",            "cve":"CVE-1999-0619",    "cvss":9.8,  "action":"Disable Telnet immediately; replace with SSH."},
    "ssh":           {"bonus":1, "name":"SSH Exposed",                 "cve":"CVE-2023-38408",   "cvss":5.0,  "action":"Restrict SSH; enforce key-based auth only."},
    "smtp":          {"bonus":2, "name":"Open SMTP Relay",             "cve":"CVE-2020-7247",    "cvss":6.5,  "action":"Disable open relay; require SMTP authentication."},
    "http":          {"bonus":1, "name":"Unencrypted HTTP",            "cve":"CWE-319",          "cvss":5.3,  "action":"Enforce HTTPS; install a valid TLS certificate."},
    "https":         {"bonus":0, "name":"HTTPS",                      "cve":"N/A",              "cvss":0.0,  "action":"Ensure TLS certificate is valid and not expired."},
    "http-proxy":    {"bonus":2, "name":"Open HTTP Proxy",             "cve":"CWE-441",          "cvss":6.1,  "action":"Restrict proxy to authorised users only."},
    "http-alt":      {"bonus":1, "name":"Alternate HTTP Port",         "cve":"CWE-16",           "cvss":5.0,  "action":"Restrict access to this alternate HTTP port."},
    "rdp":           {"bonus":4, "name":"RDP Exposed (BlueKeep risk)", "cve":"CVE-2019-0708",    "cvss":9.8,  "action":"Disable RDP or place behind VPN; apply BlueKeep patch."},
    "vnc":           {"bonus":3, "name":"VNC Exposed",                 "cve":"CVE-2006-2369",    "cvss":7.5,  "action":"Restrict VNC; enforce strong passwords and firewall."},
    "mysql":         {"bonus":3, "name":"MySQL Exposed",               "cve":"CVE-2012-2122",    "cvss":7.5,  "action":"Restrict MySQL to localhost; never expose port 3306."},
    "ms-sql-s":      {"bonus":3, "name":"MSSQL Server Exposed",        "cve":"CVE-2020-0618",    "cvss":7.2,  "action":"Firewall port 1433; apply latest SQL Server patches."},
    "smb":           {"bonus":4, "name":"SMB Exposed (EternalBlue)",   "cve":"CVE-2017-0144",    "cvss":9.3,  "action":"Block ports 139/445 at perimeter; apply MS17-010 patch."},
    "netbios-ssn":   {"bonus":3, "name":"NetBIOS Session Exposed",     "cve":"CVE-2017-0144",    "cvss":8.1,  "action":"Block all NetBIOS ports at the firewall."},
    "pop3":          {"bonus":2, "name":"Cleartext POP3",              "cve":"CWE-523",          "cvss":5.9,  "action":"Use POP3S on port 995 with TLS enabled."},
    "imap":          {"bonus":2, "name":"Cleartext IMAP",              "cve":"CWE-523",          "cvss":5.9,  "action":"Use IMAPS on port 993 with TLS enabled."},
    "dns":           {"bonus":2, "name":"Open DNS Resolver",           "cve":"CVE-2008-1447",    "cvss":6.8,  "action":"Disable recursive DNS queries; enable rate limiting."},
    "ntp":           {"bonus":1, "name":"NTP Amplification Risk",      "cve":"CVE-2013-5211",    "cvss":5.0,  "action":"Disable NTP monlist; restrict NTP queries by ACL."},
    "snmp":          {"bonus":3, "name":"SNMP Exposed",                "cve":"CVE-2002-0013",    "cvss":7.8,  "action":"Disable SNMPv1/v2c; upgrade to SNMPv3 with auth."},
    "ldap":          {"bonus":2, "name":"LDAP Exposed",                "cve":"CVE-2021-44228",   "cvss":10.0, "action":"Restrict LDAP access; patch Log4Shell vulnerabilities."},
    "mongodb":       {"bonus":3, "name":"MongoDB No Auth",             "cve":"CVE-2013-2916",    "cvss":7.5,  "action":"Enable MongoDB authentication; bind to localhost."},
    "redis":         {"bonus":4, "name":"Redis Exposed (No Auth)",     "cve":"CVE-2015-4335",    "cvss":9.3,  "action":"Set Redis requirepass; bind to 127.0.0.1 only."},
    "elasticsearch": {"bonus":3, "name":"Elasticsearch Exposed",       "cve":"CVE-2015-1427",    "cvss":10.0, "action":"Enable X-Pack security; firewall port 9200."},
    "postgresql":    {"bonus":2, "name":"PostgreSQL Exposed",          "cve":"CVE-2019-10164",   "cvss":8.8,  "action":"Restrict PostgreSQL to app server only."},
    "memcached":     {"bonus":3, "name":"Memcached Amplification",     "cve":"CVE-2018-1000115", "cvss":7.5,  "action":"Disable Memcached UDP; bind to localhost."},
    "rpcbind":       {"bonus":2, "name":"RPC Portmapper Exposed",      "cve":"CVE-2017-8779",    "cvss":7.5,  "action":"Block port 111 at firewall; disable rpcbind."},
    "nfs":           {"bonus":3, "name":"NFS Share Exposed",           "cve":"CVE-2019-3010",    "cvss":7.8,  "action":"Restrict NFS exports; require strong authentication."},
    "msrpc":         {"bonus":2, "name":"MS-RPC Exposed",              "cve":"CVE-2003-0352",    "cvss":7.5,  "action":"Firewall MS-RPC ports 135 and 445."},
    "irc":           {"bonus":2, "name":"IRC Service Exposed",         "cve":"CVE-2010-2956",    "cvss":6.4,  "action":"Disable IRC; block port 6667 at firewall."},
    "docker":        {"bonus":4, "name":"Docker API Exposed",          "cve":"CVE-2019-5736",    "cvss":9.0,  "action":"Never expose Docker daemon to internet; use TLS."},
    "jenkins":       {"bonus":3, "name":"Jenkins CI Exposed",          "cve":"CVE-2019-1003000", "cvss":9.8,  "action":"Disable anonymous access; place Jenkins behind VPN."},
    "winrm":         {"bonus":3, "name":"WinRM Exposed",               "cve":"CVE-2021-31166",   "cvss":9.8,  "action":"Restrict WinRM; use HTTPS + IP whitelisting."},
    "rsync":         {"bonus":2, "name":"Rsync Exposed",               "cve":"CVE-2014-9512",    "cvss":6.4,  "action":"Restrict rsync with authentication + IP whitelist."},
    "cups":          {"bonus":2, "name":"CUPS Print Server",           "cve":"CVE-2024-47176",   "cvss":9.9,  "action":"Disable CUPS internet exposure immediately."},
    "x11":           {"bonus":3, "name":"X11 Display Server Exposed",  "cve":"CVE-2011-4613",    "cvss":7.5,  "action":"Never expose X11 to internet; use SSH X forwarding."},
    "oracle":        {"bonus":3, "name":"Oracle DB Exposed",           "cve":"CVE-2020-14871",   "cvss":9.8,  "action":"Firewall Oracle DB ports; apply all patches."},
    "unknown":       {"bonus":1, "name":"Unknown Service",             "cve":"N/A",              "cvss":5.0,  "action":"Investigate this service and close if not required."},
}


def get_vuln(service: str) -> dict:
    """Return the vulnerability entry for a service, defaulting to 'unknown'."""
    return VULN_DB.get(service.lower().strip(), VULN_DB["unknown"])


def is_valid_target(target: str) -> bool:
    """Check whether a target is a valid IP, hostname, or CIDR notation."""
    t = target.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", t):
        return True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
        return all(0 <= int(p) <= 255 for p in t.split("."))
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", t):
        return True
    return False


def calc_risk(service: str, malicious_reports: int) -> int:
    """Calculate a risk score 1-10: base 1 + service bonus + VT malicious count."""
    bonus = get_vuln(service)["bonus"]
    return min(10, 1 + bonus + malicious_reports)


def classify_severity(score: int) -> str:
    """Map a numeric risk score to a severity label."""
    if   score >= 9: return "Critical"
    elif score >= 7: return "High"
    elif score >= 4: return "Medium"
    elif score >= 1: return "Low"
    else:            return "Informational"


def run_nmap(target: str) -> str:
    """
    Run an Nmap scan on the given target and save the XML output.
    Returns the path to the saved XML file.

    Flags:
      -Pn    skip host-discovery ping (many hosts block ICMP)
      -sV    detect service names and versions
      --open only show ports that are open
      -p     our custom port list
      -oX    save XML output for Python to parse
    """
    safe   = re.sub(r"[/: ]", "_", target)
    xmlout = os.path.join(SCAN_DIR, f"{safe}.xml")
    cmd = ["nmap", "-Pn", "-sV", "--open", "-p", SCAN_PORTS, "-oX", xmlout, target]
    try:
        subprocess.run(cmd, capture_output=True, timeout=200)
        logger.info(f"Nmap completed for {target}")
    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap timed out for {target}")
    except FileNotFoundError:
        logger.error("Nmap not found - install from https://nmap.org/download.html")
    return xmlout


def parse_nmap_xml(xmlpath: str) -> list:
    """
    Parse the Nmap XML output file.
    Returns a list of dicts, one per open port found.
    """
    rows = []
    if not os.path.exists(xmlpath):
        return rows
    try:
        root = ET.parse(xmlpath).getroot()
        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "unknown")
            hn_el    = host.find(".//hostname")
            hostname = hn_el.get("name", ip) if hn_el is not None else ip

            for port_el in host.findall(".//port"):
                portid  = port_el.get("portid", "0")
                svc_el  = port_el.find("service")
                svc     = svc_el.get("name",    "unknown") if svc_el is not None else "unknown"
                product = svc_el.get("product", "")        if svc_el is not None else ""
                version = svc_el.get("version", "")        if svc_el is not None else ""
                rows.append({
                    "ip": ip, "hostname": hostname,
                    "port": portid, "service": svc,
                    "product": product, "version": version,
                })
    except Exception as exc:
        logger.error(f"XML parse error for {xmlpath}: {exc}")
    return rows


def check_virustotal(ip: str, api_key: str, retries: int = 3) -> dict:
    """
    Query the VirusTotal v3 API for threat intelligence on an IP address.
    Returns a dict of malicious/suspicious/harmless counts and location info.
    The free tier allows 4 requests per minute - caller should pace calls.
    """
    default = {
        "malicious_reports": 0, "suspicious_count": 0,
        "harmless_count":    0, "community_score":  0,
        "country": "Unknown", "network": "Unknown", "categories": "",
    }
    if not api_key or api_key.startswith("your_"):
        return default

    url     = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 429:          # rate limit
                wait = 2 ** attempt * 15
                logger.warning(f"VT rate limit for {ip}; waiting {wait}s")
                time.sleep(wait)
                continue
            if r.status_code != 200:
                return default
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            cats  = attrs.get("categories", {})
            return {
                "malicious_reports": stats.get("malicious",  0),
                "suspicious_count":  stats.get("suspicious", 0),
                "harmless_count":    stats.get("harmless",   0),
                "community_score":   attrs.get("reputation", 0),
                "country":           attrs.get("country",    "Unknown"),
                "network":           attrs.get("network",    "Unknown"),
                "categories":        ", ".join(cats.values()) if cats else "",
            }
        except Exception as exc:
            logger.error(f"VT error for {ip} attempt {attempt+1}: {exc}")
            time.sleep(5)
    return default


def run_full_pipeline(targets: list, vt_api_key: str, progress_cb=None) -> list:
    """
    Run the complete scan pipeline for a list of targets:
      1. Nmap scan each target
      2. VirusTotal enrichment per unique IP
      3. Attach risk scores and vulnerability metadata

    progress_cb(pct: float, message: str) - optional progress callback
    Returns a list of enriched row dicts ready for a DataFrame.
    """
    all_rows   = []
    n_targets  = len(targets)

    def _cb(pct, msg):
        if progress_cb:
            progress_cb(pct, msg)
        logger.info(f"[{pct:.0%}] {msg}")

    # Phase 1 - Nmap
    for i, tgt in enumerate(targets):
        _cb((i + 0.5) / (n_targets * 2), f"Nmap scanning {tgt} …")
        xml  = run_nmap(tgt)
        rows = parse_nmap_xml(xml)
        all_rows.extend(rows)
        _cb((i + 1) / (n_targets * 2), f"Nmap done for {tgt} - {len(rows)} port(s) found")

    if not all_rows:
        _cb(1.0, "Nmap found no open ports")
        return []

    # Phase 2 - VirusTotal
    import pandas as pd
    df         = pd.DataFrame(all_rows)
    unique_ips = df["ip"].unique().tolist()
    vt_cache   = {}
    n_total    = n_targets + len(unique_ips)

    for j, ip in enumerate(unique_ips):
        _cb((n_targets + j + 0.5) / n_total, f"VirusTotal checking {ip} …")
        vt_cache[ip] = check_virustotal(ip, vt_api_key)
        _cb((n_targets + j + 1) / n_total, f"VT done for {ip}")
        if j < len(unique_ips) - 1:
            time.sleep(16)   # free VT tier = 4 req/min

    # Phase 3 - Enrich rows
    enriched = []
    for row in all_rows:
        vt    = vt_cache.get(row["ip"], {})
        score = calc_risk(row["service"], vt.get("malicious_reports", 0))
        sev   = classify_severity(score)
        vuln  = get_vuln(row["service"])
        enriched.append({
            **row, **vt,
            "risk_score":    score,
            "severity":      sev,
            "vulnerability": vuln["name"],
            "cve_ref":       vuln["cve"],
            "cvss":          vuln["cvss"],
            "action":        vuln["action"],
        })

    _cb(1.0, f"Complete - {len(enriched)} finding(s) across {len(unique_ips)} host(s)")
    return enriched
