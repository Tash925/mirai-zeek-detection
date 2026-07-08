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
sqlite3 investigation.db < queries/03_port_signatures.sql
sqlite3 investigation.db < queries/04_host_summary.sql
```

## 🔍 What this toolkit detects

| Query | Detects | Key finding from my hunt |
|---|---|---|
| `01_baseline` | Network-wide connection health | 647,224 S0 attempts — 60%+ never completed |
| `02_failed_connections` | The source host of the S0 flood | `192.168.10.43` — 513,865 S0 (79% of all unanswered) |
| `03_port_signatures` | Mirai port targeting | Ports 23, 22, 2323 — the Mirai signature |
| `04_host_summary` | Full threat profile in one query | `.43` at 17.7% success vs. clean host at 94.6% |

## 📖 The full investigation

- **[Part 1 — From Raw Log to Botnet Discovery](writeups/part1-botnet-discovery.md)**
- **[Part 2 — C2 Beaconing, Brute Force & the SSH Intrusion](writeups/part2-c2-brute-force-ssh.md)**

Originally published on [DataSec Chronicles](https://datasecchronicles.com).

## 🧰 Tools & concepts

**Tools:** SQLite · SQL · Zeek `conn.log` · command-line log prep
**Concepts:** anomaly detection · connection-state (S0) analysis · Mirai port signatures · scanning identification · lateral movement · kill-chain reconstruction

*Part 2 (forthcoming) extends this with C2 beaconing, attack-timing analysis, and external SSH brute-force detection.*

## 📂 What's in here

- `queries/` — the SQL, in investigation order, each documented with purpose and finding
- `setup/` — schema and import steps to reproduce the environment
- `findings/` — summary of results and query-output screenshots
- `writeups/` — the full narrative in two parts

## 📝 Note on the data

This investigation used a public Zeek/Corelight dataset from Kaggle: [DNS and Connections Log](https://www.kaggle.com/datasets/mimansari/dns-and-connections-log-zeek-or-corelight). The `conn.log` (1,319,960 records) is the source for every query here. All IPs are from that public dataset.

---

*Part of my transition from data analytics into cybersecurity — documented in public at [DataSec Chronicles](https://datasecchronicles.com).* 🖤
