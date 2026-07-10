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
sqlite3 investigation.db < queries/05_c2_beaconing.sql
sqlite3 investigation.db < queries/06_internal_recon.sql
sqlite3 investigation.db < queries/07_ssh_bruteforce.sql
sqlite3 investigation.db < queries/08_intruder_deepdive.sql
sqlite3 investigation.db < queries/09_services.sql
sqlite3 investigation.db < queries/10_timeline.sql
```

## 🔍 What this toolkit detects

| Query | Detects | Key finding from my hunt |
|---|---|---|
| `01_baseline` | Network-wide connection health | 647,224 S0 attempts — 60%+ never completed |
| `02_failed_connections` | The source host of the S0 flood | `192.168.10.43` — 513,865 S0 (79% of all unanswered) |
| `03_port_signatures` | Mirai port targeting | Ports 23, 22, 2323 — the Mirai signature |
| `04_host_summary` | Full threat profile in one query | `.43` at 17.7% success vs. clean host at 94.6% |
| `05_c2_beaconing` | C2 beaconing (regularity, not average) | `192.168.60.22` → 4 external C2 servers at ~755s cadence (CV<0.1) |
| `06_internal_recon` | Internal reconnaissance / lateral movement | `192.168.10.50` swept 771 internal hosts (HTTPS+ICMP sweep, targeted SMB/RPC/FTP) |
| `07_ssh_bruteforce` | External SSH brute-force campaigns | Multiple external IPs; sequential `.133`/`.134` pair — coordinated |
| `08_intruder_deepdive` | Successful intrusion vs. failed brute force | `5.45.85.158` → `.43`: 3h18m session, ~4MB — confirmed inside |
| `09_services` | "Normal" traffic during the breach | 74,614 HTTP sessions completed while the breach was active |
| `10_timeline` | Incident chronology reconstruction | Recon + C2 active ~28h *before* the SSH intrusion — network already compromised |

## 📖 The full investigation

- **[Part 1 — From Raw Log to Botnet Discovery](writeups/part1-botnet-discovery.md)**
- **[Part 2 — C2 Beaconing, Internal Recon & the SSH Intrusion](writeups/part2-c2-brute-force-ssh.md)**

Originally published on [DataSec Chronicles](https://datasecchronicles.com).

## 🧰 Tools & concepts

**Tools:** SQLite · SQL · Zeek `conn.log` · command-line log prep
**Concepts:** anomaly detection · connection-state (S0) analysis · Mirai port signatures · scanning identification · beacon detection via coefficient of variation · internal reconnaissance · kill-chain reconstruction

*Part 2 extends this with C2 beacon detection (using statistical regularity to separate real beacons from bursty false positives), internal reconnaissance / lateral movement, and external SSH brute-force detection — including a confirmed intrusion.*

## 📂 What's in here

- `queries/` — the SQL, in investigation order, each documented with purpose and finding
- `setup/` — schema and import steps to reproduce the environment
- `findings/` — summary of results and query-output screenshots
- `writeups/` — the full narrative in two parts

## 📝 Note on the data

This investigation used a public Zeek/Corelight dataset from Kaggle: [DNS and Connections Log](https://www.kaggle.com/datasets/mimansari/dns-and-connections-log-zeek-or-corelight). The `conn.log` (1,319,960 records) is the source for every query here. All IPs are from that public dataset.

---

*Part of my transition from data analytics into cybersecurity — documented in public at [DataSec Chronicles](https://datasecchronicles.com).* 🖤
