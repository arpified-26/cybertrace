"""
database.py — CyberTrace SQLite persistence layer

Stores each uploaded log scan as a "run", along with its parsed events and
generated alerts, so past scans can be reviewed later from the dashboard.
"""

import sqlite3
import pandas as pd
from datetime import datetime

DB_PATH = "cybertrace.db"


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        scanned_at TEXT,
        total_events INTEGER,
        suspicious_events INTEGER,
        critical_alerts INTEGER
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        timestamp TEXT,
        event_type TEXT,
        user TEXT,
        ip TEXT,
        status TEXT,
        raw TEXT,
        FOREIGN KEY(run_id) REFERENCES runs(run_id)
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        timestamp TEXT,
        rule TEXT,
        severity TEXT,
        detail TEXT,
        ip TEXT,
        user TEXT,
        count INTEGER,
        FOREIGN KEY(run_id) REFERENCES runs(run_id)
    );
    """)
    conn.commit()


def save_run(conn, filename: str, events_df: pd.DataFrame, alerts_df: pd.DataFrame) -> int:
    """Persist a completed scan. Returns the new run_id."""
    total_events = len(events_df)
    suspicious_events = int(alerts_df["count"].sum()) if not alerts_df.empty else 0
    critical_alerts = int((alerts_df["severity"] == "Critical").sum()) if not alerts_df.empty else 0

    cur = conn.execute(
        "INSERT INTO runs (filename, scanned_at, total_events, suspicious_events, critical_alerts) "
        "VALUES (?, ?, ?, ?, ?)",
        (filename, datetime.now().isoformat(timespec="seconds"),
         total_events, suspicious_events, critical_alerts),
    )
    run_id = cur.lastrowid

    if not events_df.empty:
        ev = events_df.copy()
        ev["run_id"] = run_id
        ev["timestamp"] = ev["timestamp"].astype(str)
        ev[["run_id", "timestamp", "event_type", "user", "ip", "status", "raw"]].to_sql(
            "events", conn, if_exists="append", index=False
        )

    if not alerts_df.empty:
        al = alerts_df.copy()
        al["run_id"] = run_id
        al["timestamp"] = al["timestamp"].astype(str)
        al[["run_id", "timestamp", "rule", "severity", "detail", "ip", "user", "count"]].to_sql(
            "alerts", conn, if_exists="append", index=False
        )

    conn.commit()
    return run_id


def list_runs(conn) -> pd.DataFrame:
    return pd.read_sql(
        "SELECT * FROM runs ORDER BY run_id DESC", conn
    )


def load_run_alerts(conn, run_id: int) -> pd.DataFrame:
    return pd.read_sql(
        "SELECT * FROM alerts WHERE run_id = ? ORDER BY severity, timestamp DESC",
        conn, params=(run_id,)
    )


def load_run_events(conn, run_id: int) -> pd.DataFrame:
    return pd.read_sql(
        "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp",
        conn, params=(run_id,)
    )
