"""
app.py — CyberTrace: Security Log Analyzer
Run with:  streamlit run app.py
"""

import streamlit as st
import pandas as pd
import altair as alt

from parser import parse_log_text
from detectors import run_all, DEFAULT_CONFIG
from database import get_connection, init_db, save_run, list_runs, load_run_alerts, load_run_events

st.set_page_config(
    page_title="CyberTrace — Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# DB init (cached across reruns)
# ---------------------------------------------------------------------------
@st.cache_resource
def _db():
    conn = get_connection()
    init_db(conn)
    return conn

conn = _db()

SEV_COLOR = {"Critical": "#e74c3c", "Warning": "#f39c12", "Info": "#3498db"}
SEV_ICON = {"Critical": "🔴", "Warning": "🟠", "Info": "🔵"}

# ---------------------------------------------------------------------------
# Sidebar — upload + detection thresholds
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ CyberTrace")
st.sidebar.caption("Security Log Analyzer")

uploaded = st.sidebar.file_uploader(
    "Upload a log file (.log / .txt)", type=["log", "txt", "csv"]
)

with st.sidebar.expander("⚙️ Detection thresholds", expanded=False):
    cfg = dict(DEFAULT_CONFIG)
    cfg["brute_force_threshold"] = st.slider("Brute-force: failed logins to flag", 2, 20, cfg["brute_force_threshold"])
    cfg["brute_force_window_min"] = st.slider("Brute-force: window (minutes)", 1, 60, cfg["brute_force_window_min"])
    cfg["cred_stuffing_users"] = st.slider("Credential stuffing: distinct users/IP", 2, 20, cfg["cred_stuffing_users"])
    cfg["suspicious_ip_fail_rate"] = st.slider("Suspicious IP: fail-rate threshold", 0.1, 1.0, cfg["suspicious_ip_fail_rate"])
    cfg["freq_threshold"] = st.slider("Request frequency: events/min from one IP", 5, 200, cfg["freq_threshold"])
    unusual_range = st.slider("Unusual login hours (24h)", 0, 23, (cfg["unusual_hour_start"], cfg["unusual_hour_end"]))
    cfg["unusual_hour_start"], cfg["unusual_hour_end"] = unusual_range

st.sidebar.divider()
st.sidebar.subheader("📜 Scan history")
runs_df = list_runs(conn)
history_choice = None
if not runs_df.empty:
    labels = [
        f"#{r.run_id} · {r.filename} · {r.scanned_at}" for r in runs_df.itertuples()
    ]
    picked = st.sidebar.selectbox("View a past scan", ["(current upload)"] + labels)
    if picked != "(current upload)":
        history_choice = int(picked.split("·")[0].strip().lstrip("#"))
else:
    st.sidebar.caption("No scans yet.")

# ---------------------------------------------------------------------------
# Main: load either the uploaded file or a picked historical run
# ---------------------------------------------------------------------------
st.title("🛡️ CyberTrace — Security Log Analyzer")

events_df, alerts_df, source_label = None, None, None

if history_choice is not None:
    events_df = load_run_events(conn, history_choice)
    events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])
    alerts_df = load_run_alerts(conn, history_choice)
    alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
    source_label = f"Viewing past scan #{history_choice}"

elif uploaded is not None:
    raw_text = uploaded.read().decode("utf-8", errors="ignore")
    events_df = parse_log_text(raw_text)
    alerts_df = run_all(events_df, cfg)
    save_run(conn, uploaded.name, events_df, alerts_df)
    st.cache_resource.clear()  # refresh history list next render... but keep this run visible
    conn = get_connection()
    init_db(conn)
    source_label = f"Just analyzed: {uploaded.name}"

else:
    st.info(
        "👈 Upload a log file to get started, or try the bundled sample at "
        "`sample_data/sample.log` (generate it with `python sample_data/generate_sample_log.py`)."
    )
    with st.expander("Example log formats CyberTrace understands"):
        st.code(
            "2026-09-14 03:12:45 FAILED LOGIN — user: admin, ip: 192.168.1.5\n"
            "FAILED LOGIN — user: admin\n"
            "Sep 14 03:12:45 server sshd[1234]: Failed password for admin from 192.168.1.5 port 22\n"
            '192.168.1.5 - - [14/Sep/2026:03:12:45 +0000] "POST /login HTTP/1.1" 401 512',
            language="text",
        )
    st.stop()

# ---------------------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------------------
st.caption(source_label)

total_events = len(events_df)
suspicious_events = int(alerts_df["count"].sum()) if not alerts_df.empty else 0
critical_alerts = int((alerts_df["severity"] == "Critical").sum()) if not alerts_df.empty else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", f"{total_events:,}")
c2.metric("Suspicious Events", f"{suspicious_events:,}")
c3.metric("Critical Alerts", f"{critical_alerts:,}")
c4.metric("Alert Rules Triggered", f"{alerts_df['rule'].nunique() if not alerts_df.empty else 0}")

if critical_alerts > 0:
    st.error(f"🚨 {critical_alerts} Critical alert(s) detected — review below.")
elif not alerts_df.empty:
    st.warning(f"⚠️ {len(alerts_df)} suspicious pattern(s) detected.")
else:
    st.success("✅ No suspicious activity detected.")

st.divider()

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Event activity over time")
    if not events_df.empty:
        ts = events_df.copy()
        ts["bucket"] = ts["timestamp"].dt.floor("min")
        counts = ts.groupby(["bucket", "event_type"]).size().reset_index(name="count")
        chart = (
            alt.Chart(counts)
            .mark_area(opacity=0.7)
            .encode(
                x=alt.X("bucket:T", title="Time"),
                y=alt.Y("count:Q", title="Events", stack="zero"),
                color=alt.Color("event_type:N", title="Event type"),
                tooltip=["bucket:T", "event_type:N", "count:Q"],
            )
            .properties(height=300)
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        st.caption("No events to chart.")

with col2:
    st.subheader("Alert severity")
    if not alerts_df.empty:
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        chart = (
            alt.Chart(sev_counts)
            .mark_arc(innerRadius=50)
            .encode(
                theta="count:Q",
                color=alt.Color(
                    "severity:N",
                    scale=alt.Scale(
                        domain=["Critical", "Warning", "Info"],
                        range=[SEV_COLOR["Critical"], SEV_COLOR["Warning"], SEV_COLOR["Info"]],
                    ),
                ),
                tooltip=["severity:N", "count:Q"],
            )
            .properties(height=300)
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        st.caption("No alerts to chart.")

st.subheader("Top IPs by event volume")
if not events_df.empty:
    top_ips = (
        events_df[events_df["ip"] != "unknown"]["ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )
    top_ips.columns = ["ip", "events"]
    if not top_ips.empty:
        bar = (
            alt.Chart(top_ips)
            .mark_bar()
            .encode(
                x=alt.X("events:Q"),
                y=alt.Y("ip:N", sort="-x"),
                tooltip=["ip:N", "events:Q"],
                color=alt.value("#2980b9"),
            )
            .properties(height=300)
        )
        st.altair_chart(bar, use_container_width=True)
    else:
        st.caption("No IP data found in this log.")

st.divider()

# ---------------------------------------------------------------------------
# Alerts table
# ---------------------------------------------------------------------------
st.subheader("🚨 Detected alerts")
if alerts_df.empty:
    st.caption("No alerts triggered with the current thresholds.")
else:
    sev_filter = st.multiselect(
        "Filter by severity", ["Critical", "Warning", "Info"],
        default=["Critical", "Warning", "Info"]
    )
    rule_filter = st.multiselect(
        "Filter by rule", sorted(alerts_df["rule"].unique()),
        default=sorted(alerts_df["rule"].unique())
    )
    filtered = alerts_df[
        alerts_df["severity"].isin(sev_filter) & alerts_df["rule"].isin(rule_filter)
    ].copy()
    filtered["severity"] = filtered["severity"].apply(lambda s: f"{SEV_ICON.get(s,'')} {s}")

    st.dataframe(
        filtered[["timestamp", "severity", "rule", "detail", "ip", "user", "count"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
            "count": st.column_config.NumberColumn("Magnitude"),
        },
    )

    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download alerts as CSV", csv, "cybertrace_alerts.csv", "text/csv")

st.divider()

# ---------------------------------------------------------------------------
# Raw events viewer
# ---------------------------------------------------------------------------
with st.expander("📄 View raw parsed events"):
    st.dataframe(
        events_df[["timestamp", "event_type", "user", "ip", "status", "raw"]],
        use_container_width=True,
        hide_index=True,
    )
