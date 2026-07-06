# 🛡️ Mirai Detection Toolkit — Zeek Log Threat Hunt with SQL

> A reusable set of SQL queries and an investigation walkthrough for detecting a Mirai botnet infection in raw Zeek `conn.log` data — no SIEM required.

This repo packages a real threat hunt I conducted: loading a raw Zeek network log into SQLite and using SQL to identify, scope, and document a **Mirai botnet infection** from scratch. The queries are reusable; the writeups explain the reasoning at each step.

**Built by a data analyst applying anomaly-detection instincts to network defense.**

---

## 🚀 Quick start

```bash
# 1. Prep the log (strip Zeek metadata headers) and load into SQLite
sqlite3 investigation.db < setup/schema.sql
# (see setup/import_notes.md for the header-strip + import steps)

# 2. Run the investigation queries in order
sqlite3 investigation.db < queries/01_baseline.sql
sqlite3 investigation.db < queries/02_failed_connections.sql
# ...through 08
```

## 🔍 What this toolkit detects

| Query | Detects | Key finding from my hunt |
|---|---|---|
| `01_baseline` | Normal connection behavior | 94.6% success on clean hosts |
| `02_failed_connections` | Scanning behavior (S0 flood) | `192.168.10.43` — 513,865 failed attempts |
| `03_port_signatures` | Mirai port targeting | Ports 23, 22, 2323, 2222 |
| `04_lateral_movement` | Internal spread | Across 4 subnets |
| `05_c2_beaconing` | Command-and-control | Fixed 999-byte payloads |
| `06_timeline_cadence` | Automation rhythm | 36-second attack cadence |
| `07_peer_coordination` | Infected-host coordination | 95,716 p2p connections |
| `08_ssh_intrusion` | External entry point | `5.45.85.158`, 1.6M+ bytes, 3h+ sessions |

## 📖 The full investigation

- **[Part 1 — From Raw Log to Botnet Discovery](writeups/part1-botnet-discovery.md)**
- **[Part 2 — C2 Beaconing, Brute Force & the SSH Intrusion](writeups/part2-c2-brute-force-ssh.md)**

Originally published on [DataSec Chronicles](https://datasecchronicles.com).

## 🧰 Tools & concepts

**Tools:** SQLite · SQL · Zeek `conn.log` · command-line log prep
**Concepts:** anomaly detection · Mirai signatures · C2 beaconing · lateral movement · brute-force detection · connection-state (S0) analysis

## 📂 What's in here

- `queries/` — the SQL, in investigation order, each documented with purpose and finding
- `setup/` — schema and import steps to reproduce the environment
- `findings/` — summary of results and query-output screenshots
- `writeups/` — the full narrative in two parts

## 📝 Note on the data

This investigation used a practice Zeek dataset. The internal IPs are from that lab environment.

---

*Part of my transition from data analytics into cybersecurity — documented in public at [DataSec Chronicles](https://datasecchronicles.com).* 🖤
