# 🛡️ CyberTrace — Security Log Analyzer

Upload a server/application log file and CyberTrace flags suspicious activity
and shows it on a live dashboard, backed by SQLite so past scans are saved.

**Stack:** Python + Pandas + Streamlit + SQLite (charts via Altair)

## What it detects

| Detector | What it catches |
|---|---|
| 🔴 Brute-Force Attack | Repeated failed logins for the same user or IP within a rolling time window |
| 🟠 Unusual Login Time | Logins during off-hours (default: midnight–5am, configurable) |
| 🔴 Credential Stuffing | One IP trying many different usernames in a short window |
| 🟠 Suspicious IP Activity | An IP with an abnormally high failed-login rate |
| 🟠 Abnormal Request Frequency | An IP generating way more events per minute than normal |

Every alert gets a severity (`Critical` / `Warning` / `Info`) based on how far
past the threshold it is. Thresholds are all adjustable live from the sidebar.

## Setup

```bash
cd cybertrace
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Generate a demo log (optional but recommended)

```bash
python sample_data/generate_sample_log.py
```

This writes `sample_data/sample.log` containing normal traffic mixed with a
brute-force attack, a credential-stuffing burst, a suspicious IP, and a
request-frequency spike — good for seeing every detector fire.

## Run the dashboard

```bash
streamlit run app.py
```

Then open the local URL Streamlit prints (usually `http://localhost:8501`),
and upload `sample_data/sample.log` (or your own log file) via the sidebar.

## Supported log formats

CyberTrace auto-detects several common formats line by line, so you can feed
it real logs without pre-processing:

```
2026-09-14 03:12:45 FAILED LOGIN — user: admin, ip: 192.168.1.5
FAILED LOGIN — user: admin
Sep 14 03:12:45 server sshd[1234]: Failed password for admin from 192.168.1.5 port 22
192.168.1.5 - - [14/Sep/2026:03:12:45 +0000] "POST /login HTTP/1.1" 401 512
```

Lines that don't match a known pattern are kept and labeled `UNKNOWN` rather
than dropped, so you can still see them in the raw event viewer.

## Project structure

```
cybertrace/
├── app.py                          # Streamlit dashboard (entry point)
├── parser.py                       # Log-line parsing & normalization
├── detectors.py                    # Detection rules / scoring logic
├── database.py                     # SQLite persistence (scan history)
├── requirements.txt
├── sample_data/
│   └── generate_sample_log.py      # Creates a realistic demo log
└── cybertrace.db                   # Created automatically on first run
```

## Tuning detection sensitivity

Open the "⚙️ Detection thresholds" panel in the sidebar to adjust, live:

- Failed-login count / time window that counts as brute force
- Distinct-username count that counts as credential stuffing
- Failed-login rate that marks an IP as suspicious
- Events/minute that counts as abnormal frequency
- Which hours count as "unusual" login times

## Extending it

- Add a new detector: write a function in `detectors.py` following the same
  pattern (take `df` + `cfg`, return a list of alert dicts), then call it
  inside `run_all()`.
- Add a new log format: add a regex + extraction branch in `parser.py`.
- Alerts and raw events are both queryable straight from `cybertrace.db` if
  you want to build additional reporting outside the dashboard.
