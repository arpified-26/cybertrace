"""
generate_sample_log.py — Creates a realistic demo log with normal traffic
mixed with several attack patterns, so you can test CyberTrace immediately.

Usage:
    python sample_data/generate_sample_log.py
Produces:
    sample_data/sample.log
"""

import random
from datetime import datetime, timedelta

random.seed(42)

start = datetime(2026, 9, 14, 0, 0, 0)
lines = []

normal_users = ["jsmith", "amiller", "rkumar", "lchen", "tgarcia", "kwilson"]
normal_ips = [f"10.0.0.{n}" for n in (5, 12, 27, 34, 41, 58)]

def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# --- 1. Normal daytime traffic -------------------------------------------
t = start.replace(hour=8)
for _ in range(120):
    user = random.choice(normal_users)
    ip = random.choice(normal_ips)
    t += timedelta(seconds=random.randint(20, 240))
    outcome = "LOGIN_SUCCESS" if random.random() > 0.05 else "FAILED LOGIN"
    label = "SUCCESSFUL LOGIN" if outcome == "LOGIN_SUCCESS" else "FAILED LOGIN"
    lines.append(f"{ts(t)} {label} — user: {user}, ip: {ip}")

# --- 2. Brute-force attack on 'admin' from one IP, late night ------------
attacker_ip = "203.0.113.77"
t = start.replace(hour=2, minute=10)
for _ in range(14):
    t += timedelta(seconds=random.randint(3, 15))
    lines.append(f"{ts(t)} FAILED LOGIN — user: admin, ip: {attacker_ip}")
t += timedelta(seconds=5)
lines.append(f"{ts(t)} SUCCESSFUL LOGIN — user: admin, ip: {attacker_ip}")  # eventually got in

# --- 3. Credential stuffing: one IP, many usernames -----------------------
stuffer_ip = "198.51.100.23"
t = start.replace(hour=3, minute=30)
victims = ["admin", "root", "test", "guest", "backup", "svc_acct", "jsmith", "sa"]
for user in victims:
    t += timedelta(seconds=random.randint(2, 8))
    lines.append(f"{ts(t)} FAILED LOGIN — user: {user}, ip: {stuffer_ip}")

# --- 4. Suspicious IP: mostly failures spread through the day ------------
noisy_ip = "192.0.2.150"
t = start.replace(hour=10)
for _ in range(10):
    t += timedelta(minutes=random.randint(5, 40))
    lines.append(f"{ts(t)} FAILED LOGIN — user: rkumar, ip: {noisy_ip}")
t += timedelta(minutes=10)
lines.append(f"{ts(t)} SUCCESSFUL LOGIN — user: rkumar, ip: {noisy_ip}")

# --- 5. Abnormal request frequency (scripted scan) ------------------------
scanner_ip = "203.0.113.9"
t = start.replace(hour=14, minute=0)
for _ in range(45):
    t += timedelta(seconds=random.randint(1, 3))
    lines.append(f"{ts(t)} REQUEST — user: unknown, ip: {scanner_ip}")

# --- 6. A couple of unusual-hour legit-looking logins ----------------------
t = start.replace(hour=1, minute=45)
lines.append(f"{ts(t)} SUCCESSFUL LOGIN — user: tgarcia, ip: 10.0.0.34")
t = start.replace(hour=4, minute=20)
lines.append(f"{ts(t)} SUCCESSFUL LOGIN — user: kwilson, ip: 10.0.0.58")

# --- Shuffle chronologically and write out --------------------------------
def parse_line_ts(line):
    return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")

lines.sort(key=parse_line_ts)

with open("sample_data/sample.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Wrote {len(lines)} lines to sample_data/sample.log")
