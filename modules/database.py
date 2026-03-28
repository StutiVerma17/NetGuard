# modules/database.py
# ------------------------------------------------------------------
# SQLite persistence layer
#   - Stores every scan session + all enriched rows
#   - Provides history retrieval, stats, and delete helpers
# ------------------------------------------------------------------
import sqlite3
import os
import logging
from datetime import datetime

logger  = logging.getLogger(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "netguard.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create database tables if they do not already exist."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT    NOT NULL,
                targets     TEXT    NOT NULL,
                total_hosts INTEGER DEFAULT 0,
                total_ports INTEGER DEFAULT 0,
                critical_ct INTEGER DEFAULT 0,
                high_ct     INTEGER DEFAULT 0,
                max_risk    REAL    DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_records (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id        INTEGER NOT NULL,
                ip                TEXT,
                hostname          TEXT,
                port              TEXT,
                service           TEXT,
                product           TEXT,
                version           TEXT,
                malicious_reports INTEGER DEFAULT 0,
                suspicious_count  INTEGER DEFAULT 0,
                harmless_count    INTEGER DEFAULT 0,
                community_score   INTEGER DEFAULT 0,
                country           TEXT,
                network           TEXT,
                categories        TEXT,
                risk_score        REAL    DEFAULT 0,
                severity          TEXT,
                vulnerability     TEXT,
                cve_ref           TEXT,
                cvss              REAL    DEFAULT 0,
                action            TEXT,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
        """)
        conn.commit()
    logger.info("Database initialised")


def save_scan(targets: list, rows: list) -> int:
    """Persist a completed scan session and all its rows. Returns the session ID."""
    import pandas as pd
    df = pd.DataFrame(rows) if rows else pd.DataFrame()

    started_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    targets_str = ", ".join(targets)
    total_hosts = int(df["ip"].nunique())                       if not df.empty else 0
    total_ports = len(df)                                       if not df.empty else 0
    critical_ct = int((df["severity"] == "Critical").sum())     if not df.empty else 0
    high_ct     = int((df["severity"] == "High").sum())         if not df.empty else 0
    max_risk    = float(df["risk_score"].max())                  if not df.empty else 0.0

    with _connect() as conn:
        cur = conn.execute("""
            INSERT INTO scan_sessions
                (started_at, targets, total_hosts, total_ports, critical_ct, high_ct, max_risk)
            VALUES (?,?,?,?,?,?,?)
        """, (started_at, targets_str, total_hosts, total_ports, critical_ct, high_ct, max_risk))
        session_id = cur.lastrowid

        if rows:
            conn.executemany("""
                INSERT INTO scan_records
                    (session_id,ip,hostname,port,service,product,version,
                     malicious_reports,suspicious_count,harmless_count,
                     community_score,country,network,categories,
                     risk_score,severity,vulnerability,cve_ref,cvss,action)
                VALUES
                    (:session_id,:ip,:hostname,:port,:service,:product,:version,
                     :malicious_reports,:suspicious_count,:harmless_count,
                     :community_score,:country,:network,:categories,
                     :risk_score,:severity,:vulnerability,:cve_ref,:cvss,:action)
            """, [{**r, "session_id": session_id} for r in rows])
        conn.commit()

    logger.info(f"Saved session {session_id} with {len(rows)} records")
    return session_id


def get_sessions(limit: int = 50) -> list:
    """Return the most recent scan sessions (summary rows only)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_session_records(session_id: int) -> list:
    """Return all scan records for a given session ID."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_records WHERE session_id=? ORDER BY risk_score DESC",
            (session_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_records() -> list:
    """Return every record across all sessions joined with session metadata."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT r.*, s.started_at, s.targets
            FROM scan_records r
            JOIN scan_sessions s ON r.session_id = s.id
            ORDER BY r.id DESC
        """).fetchall()
    return [dict(r) for r in rows]


def delete_session(session_id: int):
    """Delete a session and all associated records."""
    with _connect() as conn:
        conn.execute("DELETE FROM scan_records  WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM scan_sessions WHERE id=?",         (session_id,))
        conn.commit()
    logger.info(f"Deleted session {session_id}")


def get_db_stats() -> dict:
    """Return quick summary counts from the database."""
    with _connect() as conn:
        sessions = conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
        records  = conn.execute("SELECT COUNT(*) FROM scan_records").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM scan_records WHERE severity='Critical'").fetchone()[0]
        high     = conn.execute("SELECT COUNT(*) FROM scan_records WHERE severity='High'").fetchone()[0]
    return {
        "total_sessions": sessions,
        "total_records":  records,
        "critical_total": critical,
        "high_total":     high,
    }
