"""
parser.py — CyberTrace Log Parser
Normalizes raw server/application log lines into a structured pandas DataFrame.

Supported formats (auto-detected line by line):
  1. Labeled syslog-style:
       2026-09-14 03:12:45 FAILED LOGIN — user: admin, ip: 192.168.1.5
  2. Bare event lines (no timestamp/ip):
       FAILED LOGIN — user: admin
  3. SSH auth-log style:
       Sep 14 03:12:45 server sshd[1234]: Failed password for admin from 192.168.1.5 port 22
       Sep 14 03:12:50 server sshd[1234]: Accepted password for admin from 192.168.1.5 port 22
  4. Apache/nginx combined access log:
       192.168.1.5 - - [14/Sep/2026:03:12:45 +0000] "POST /login HTTP/1.1" 401 512

Any line that doesn't match a known pattern is kept as an "UNKNOWN" event so
nothing is silently dropped, and is still shown in the raw log viewer.
"""

import re
import pandas as pd
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Regex patterns, tried in order. Each returns a dict of extracted fields.
# ---------------------------------------------------------------------------

_LABELED = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<event>[A-Z_ ]+?)\s*(?:—|-|:)\s*"
    r".*?user:?\s*(?P<user>[\w.\-@]+)"
    r"(?:.*?ip:?\s*(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

_BARE = re.compile(
    r"^(?P<event>[A-Z_ ]+?)\s*(?:—|-|:)\s*"
    r".*?user:?\s*(?P<user>[\w.\-@]+)"
    r"(?:.*?ip:?\s*(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

_SSHD = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>[\w.\-@]+)\s+from\s+(?P<ip>[\d.]+)",
)

_APACHE = re.compile(
    r"^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

_CURRENT_YEAR = datetime.now().year


def _norm_event(raw_event: str, result: str = None, status: str = None) -> str:
    """Map varied phrasing to a small set of canonical event types."""
    if result:
        return "LOGIN_FAILED" if result.lower() == "failed" else "LOGIN_SUCCESS"
    if status:
        try:
            code = int(status)
        except ValueError:
            code = 0
        if code == 401 or code == 403:
            return "LOGIN_FAILED"
        if code >= 500:
            return "SERVER_ERROR"
        return "REQUEST"
    raw_event = raw_event.strip().upper()
    if "FAIL" in raw_event:
        return "LOGIN_FAILED"
    if "SUCCESS" in raw_event or "ACCEPTED" in raw_event:
        return "LOGIN_SUCCESS"
    if "LOGOUT" in raw_event:
        return "LOGOUT"
    return raw_event.replace(" ", "_") or "UNKNOWN"


def _parse_ts(ts_str: str, fallback: datetime) -> datetime:
    if not ts_str:
        return fallback
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%b %d %H:%M:%S",          # sshd style, no year
        "%d/%b/%Y:%H:%M:%S %z",    # apache style
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:  # sshd format has no year
                dt = dt.replace(year=_CURRENT_YEAR)
            return dt
        except ValueError:
            continue
    return fallback


def parse_log_text(text: str) -> pd.DataFrame:
    """Parse raw log text into a normalized DataFrame.

    Columns: timestamp, event_type, user, ip, status, raw, line_no
    """
    rows = []
    lines = [l for l in text.splitlines() if l.strip()]
    synthetic_clock = datetime.now().replace(microsecond=0)

    for i, line in enumerate(lines):
        line = line.strip()
        fallback_ts = synthetic_clock + timedelta(seconds=i)

        m = _LABELED.match(line)
        if m:
            gd = m.groupdict()
            rows.append({
                "timestamp": _parse_ts(gd.get("ts"), fallback_ts),
                "event_type": _norm_event(gd.get("event", "")),
                "user": gd.get("user") or "unknown",
                "ip": gd.get("ip") or "unknown",
                "status": None,
                "raw": line,
                "line_no": i + 1,
            })
            continue

        m = _SSHD.match(line)
        if m:
            gd = m.groupdict()
            rows.append({
                "timestamp": _parse_ts(gd.get("ts"), fallback_ts),
                "event_type": _norm_event("", result=gd.get("result")),
                "user": gd.get("user") or "unknown",
                "ip": gd.get("ip") or "unknown",
                "status": None,
                "raw": line,
                "line_no": i + 1,
            })
            continue

        m = _APACHE.match(line)
        if m:
            gd = m.groupdict()
            rows.append({
                "timestamp": _parse_ts(gd.get("ts", "").split(" ")[0], fallback_ts),
                "event_type": _norm_event("", status=gd.get("status")),
                "user": "unknown",
                "ip": gd.get("ip") or "unknown",
                "status": gd.get("status"),
                "raw": line,
                "line_no": i + 1,
            })
            continue

        m = _BARE.match(line)
        if m:
            gd = m.groupdict()
            rows.append({
                "timestamp": fallback_ts,
                "event_type": _norm_event(gd.get("event", "")),
                "user": gd.get("user") or "unknown",
                "ip": gd.get("ip") or "unknown",
                "status": None,
                "raw": line,
                "line_no": i + 1,
            })
            continue

        # Unmatched line — keep it, but mark as unknown so nothing is lost.
        rows.append({
            "timestamp": fallback_ts,
            "event_type": "UNKNOWN",
            "user": "unknown",
            "ip": "unknown",
            "status": None,
            "raw": line,
            "line_no": i + 1,
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df
