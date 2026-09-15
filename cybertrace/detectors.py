"""
detectors.py — CyberTrace Detection Engine

Each detector takes the normalized events DataFrame (see parser.py) and a
config dict, and returns a list of alert dicts:

    {
        "timestamp": datetime,
        "rule": str,            # short rule name
        "severity": str,        # "Critical" | "Warning" | "Info"
        "detail": str,          # human readable description
        "ip": str,
        "user": str,
        "count": int,           # magnitude of the anomaly, for sorting
    }

run_all() executes every detector and returns a single alerts DataFrame.
"""

import pandas as pd

DEFAULT_CONFIG = {
    "brute_force_threshold": 4,        # failed logins to trigger an alert
    "brute_force_window_min": 10,      # time window for the above
    "brute_force_critical_at": 10,     # failures within window -> Critical
    "unusual_hour_start": 0,           # 12am
    "unusual_hour_end": 5,             # 5am (exclusive)
    "cred_stuffing_users": 5,          # distinct usernames from one IP
    "cred_stuffing_window_min": 10,
    "suspicious_ip_min_attempts": 5,
    "suspicious_ip_fail_rate": 0.6,    # 60%+ failures from that IP
    "freq_window_min": 1,              # rolling window for request rate
    "freq_threshold": 30,              # events/minute from one IP
}


def _severity_from_count(count, warn_at, crit_at):
    if count >= crit_at:
        return "Critical"
    if count >= warn_at:
        return "Warning"
    return "Info"


def detect_brute_force(df: pd.DataFrame, cfg: dict) -> list:
    """Repeated failed logins by the same user OR same IP within a rolling window."""
    alerts = []
    failed = df[df["event_type"] == "LOGIN_FAILED"].copy()
    if failed.empty:
        return alerts

    window = pd.Timedelta(minutes=cfg["brute_force_window_min"])

    for key_col in ["user", "ip"]:
        if key_col == "user" and (failed["user"] == "unknown").all():
            continue
        if key_col == "ip" and (failed["ip"] == "unknown").all():
            continue
        for key, group in failed.groupby(key_col):
            if key == "unknown":
                continue
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()
            # sliding window count
            start = 0
            for end in range(len(timestamps)):
                while timestamps[end] - timestamps[start] > window:
                    start += 1
                count = end - start + 1
                if count >= cfg["brute_force_threshold"]:
                    sev = _severity_from_count(
                        count, cfg["brute_force_threshold"], cfg["brute_force_critical_at"]
                    )
                    alerts.append({
                        "timestamp": timestamps[end],
                        "rule": "Brute-Force Attack",
                        "severity": sev,
                        "detail": (
                            f"{count} failed logins for {key_col}='{key}' within "
                            f"{cfg['brute_force_window_min']} min"
                        ),
                        "ip": key if key_col == "ip" else group.iloc[-1]["ip"],
                        "user": key if key_col == "user" else group.iloc[-1]["user"],
                        "count": count,
                    })
    # Keep only the strongest alert per (rule, key) to avoid duplicate spam
    if alerts:
        alerts_df = pd.DataFrame(alerts)
        alerts_df = (
            alerts_df.sort_values("count", ascending=False)
            .drop_duplicates(subset=["rule", "ip", "user"])
        )
        alerts = alerts_df.to_dict("records")
    return alerts


def detect_unusual_times(df: pd.DataFrame, cfg: dict) -> list:
    """Successful or failed logins during off-hours (default: midnight-5am)."""
    alerts = []
    logins = df[df["event_type"].isin(["LOGIN_FAILED", "LOGIN_SUCCESS"])].copy()
    if logins.empty:
        return alerts

    logins["hour"] = logins["timestamp"].dt.hour
    start, end = cfg["unusual_hour_start"], cfg["unusual_hour_end"]
    off_hours = logins[(logins["hour"] >= start) & (logins["hour"] < end)]

    for _, row in off_hours.iterrows():
        alerts.append({
            "timestamp": row["timestamp"],
            "rule": "Unusual Login Time",
            "severity": "Warning" if row["event_type"] == "LOGIN_SUCCESS" else "Info",
            "detail": (
                f"{row['event_type'].replace('_', ' ').title()} for user='{row['user']}' "
                f"at {row['timestamp'].strftime('%H:%M')} (off-hours)"
            ),
            "ip": row["ip"],
            "user": row["user"],
            "count": 1,
        })
    return alerts


def detect_credential_stuffing(df: pd.DataFrame, cfg: dict) -> list:
    """One IP trying many distinct usernames in a short window — classic stuffing pattern."""
    alerts = []
    failed = df[df["event_type"] == "LOGIN_FAILED"].copy()
    failed = failed[failed["ip"] != "unknown"]
    if failed.empty:
        return alerts

    window = pd.Timedelta(minutes=cfg["cred_stuffing_window_min"])

    for ip, group in failed.groupby("ip"):
        group = group.sort_values("timestamp")
        rows = group[["timestamp", "user"]].to_dict("records")
        start = 0
        for end in range(len(rows)):
            while rows[end]["timestamp"] - rows[start]["timestamp"] > window:
                start += 1
            window_users = {r["user"] for r in rows[start:end + 1]}
            if len(window_users) >= cfg["cred_stuffing_users"]:
                alerts.append({
                    "timestamp": rows[end]["timestamp"],
                    "rule": "Credential Stuffing",
                    "severity": "Critical" if len(window_users) >= cfg["cred_stuffing_users"] * 2
                    else "Warning",
                    "detail": (
                        f"IP {ip} attempted {len(window_users)} distinct usernames within "
                        f"{cfg['cred_stuffing_window_min']} min"
                    ),
                    "ip": ip,
                    "user": ", ".join(sorted(window_users))[:80],
                    "count": len(window_users),
                })
    if alerts:
        adf = pd.DataFrame(alerts).sort_values("count", ascending=False)
        adf = adf.drop_duplicates(subset=["rule", "ip"])
        alerts = adf.to_dict("records")
    return alerts


def detect_suspicious_ips(df: pd.DataFrame, cfg: dict) -> list:
    """IPs with a high ratio of failed-to-total login attempts."""
    alerts = []
    logins = df[df["event_type"].isin(["LOGIN_FAILED", "LOGIN_SUCCESS"])].copy()
    logins = logins[logins["ip"] != "unknown"]
    if logins.empty:
        return alerts

    for ip, group in logins.groupby("ip"):
        total = len(group)
        if total < cfg["suspicious_ip_min_attempts"]:
            continue
        failed = (group["event_type"] == "LOGIN_FAILED").sum()
        rate = failed / total
        if rate >= cfg["suspicious_ip_fail_rate"]:
            alerts.append({
                "timestamp": group["timestamp"].max(),
                "rule": "Suspicious IP Activity",
                "severity": "Critical" if rate >= 0.85 else "Warning",
                "detail": (
                    f"IP {ip} has a {rate:.0%} failed-login rate over {total} attempts"
                ),
                "ip": ip,
                "user": "-",
                "count": failed,
            })
    return alerts


def detect_request_frequency(df: pd.DataFrame, cfg: dict) -> list:
    """Abnormally high event rate from a single IP (possible scraping / DoS / scanning)."""
    alerts = []
    scoped = df[df["ip"] != "unknown"].copy()
    if scoped.empty:
        return alerts

    window = pd.Timedelta(minutes=cfg["freq_window_min"])

    for ip, group in scoped.groupby("ip"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()
        start = 0
        best = 0
        best_ts = None
        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > window:
                start += 1
            count = end - start + 1
            if count > best:
                best, best_ts = count, timestamps[end]
        if best >= cfg["freq_threshold"]:
            alerts.append({
                "timestamp": best_ts,
                "rule": "Abnormal Request Frequency",
                "severity": "Critical" if best >= cfg["freq_threshold"] * 2 else "Warning",
                "detail": (
                    f"IP {ip} generated {best} events within {cfg['freq_window_min']} min "
                    f"(threshold: {cfg['freq_threshold']})"
                ),
                "ip": ip,
                "user": "-",
                "count": best,
            })
    return alerts


def run_all(df: pd.DataFrame, cfg: dict = None) -> pd.DataFrame:
    """Run every detector and return a combined, sorted alerts DataFrame."""
    cfg = {**DEFAULT_CONFIG, **(cfg or {})}
    if df.empty:
        return pd.DataFrame(columns=[
            "timestamp", "rule", "severity", "detail", "ip", "user", "count"
        ])

    all_alerts = []
    all_alerts += detect_brute_force(df, cfg)
    all_alerts += detect_unusual_times(df, cfg)
    all_alerts += detect_credential_stuffing(df, cfg)
    all_alerts += detect_suspicious_ips(df, cfg)
    all_alerts += detect_request_frequency(df, cfg)

    alerts_df = pd.DataFrame(all_alerts)
    if alerts_df.empty:
        return pd.DataFrame(columns=[
            "timestamp", "rule", "severity", "detail", "ip", "user", "count"
        ])

    sev_order = {"Critical": 0, "Warning": 1, "Info": 2}
    alerts_df["_sev_rank"] = alerts_df["severity"].map(sev_order)
    alerts_df = alerts_df.sort_values(
        ["_sev_rank", "timestamp"], ascending=[True, False]
    ).drop(columns="_sev_rank").reset_index(drop=True)
    return alerts_df
