# Part 2 — C2 Beaconing, Internal Recon & SSH Intrusion

*DataSec Chronicles — Mirai Detection Toolkit*
*A SQL threat hunt through a Zeek `conn.log`, re-audited against the raw data.*

---

## Overview

Part 1 identified a Mirai botnet infection: mass scanning, the telnet-family port signature, and a success-rate comparison that made the compromise undeniable. Part 2 goes deeper — and every figure here was re-run against the raw logs before it was written down. Where an early pass over-counted or mislabeled a finding, the corrected result is what appears below.

The complete incident (four distinct malicious behaviors):

- **Command & control:** `192.168.60.22` beacons to 4 external C2 servers on a ~755s cadence
- **Reconnaissance:** `192.168.10.50` sweeps 771 internal hosts to map the network
- **SSH intrusion:** external `5.45.85.158` brute-forces into `192.168.10.43`
- **Propagation:** `192.168.10.43` becomes a Mirai scanner, spraying 338,181 external IPs

A note on order: the timestamps (Finding 6) show the recon and C2 beaconing were already active more than a day *before* the SSH intrusion. The intrusion explains `.43`'s compromise — scanning starts 29 minutes after the attacker logs in — but the network was already compromised when the capture began.

---

## Finding 1 — C2 Beaconing (192.168.60.22)

**A note on method.** Beacon detection is easy to get wrong. Filtering on the *average* interval between connections over-counts, because averaging is blind to burstiness: a host that fires ten connections in half a second and then goes quiet has the same *average* gap as one connecting steadily every few seconds. One is scan spray; the other is a beacon.

The reliable test is **regularity, not average** — the coefficient of variation (standard deviation ÷ mean). A true beacon clusters tightly around its period; bursty traffic scatters. Direction matters too: beacons are outbound (internal host → external server).

Under a CV filter, one host showed genuine periodic behavior:

| Infected Host | C2 Server | Connections | Avg Interval | CV |
|---|---|---|---|---|
| 192.168.60.22 | 69.43.168.214 | 216 | 757.8s | 0.06 |
| 192.168.60.22 | 109.74.9.119 | 217 | 754.5s | 0.09 |
| 192.168.60.22 | 192.188.58.163 | 217 | 754.3s | 0.09 |
| 192.168.60.22 | 203.153.165.21 | 217 | 754.2s | 0.09 |

`192.168.60.22` beacons to **four external C2 servers** on a steady **~755-second cadence** (~12.6 minutes), held under 10% variation across 200+ callbacks each. That regularity is the signature.

> Query file: `queries/05_c2_beaconing.sql`

---

## Finding 2 — Internal Reconnaissance (192.168.10.50)

Profiling connection-success rates surfaced a second anomalous host: `192.168.10.50`, completing barely **0.5%** of its connections across 251,368 attempts.

Where `.43` fired outward at the internet, `.50` pointed **inward** — all but 3 of its connections targeted internal hosts, reaching **771 distinct internal machines**. The probing came in two phases:

| Activity | Connections | Targets | Meaning |
|---|---|---|---|
| 443 (HTTPS) | 51,686 | 768 | Broad sweep across nearly every host |
| ICMP (type 14) | 18,573 | 763 | Timestamp sweep — host discovery |
| ICMP (type 0) | 18,060 | 769 | Echo sweep — "who's alive?" |
| 445 (SMB) | 3,439 | 8 | Narrow — targeted enumeration |
| 21/135/139 (FTP/RPC/NetBIOS) | ~1,360 | 7 each | Targeted service probes |

**Broad discovery, then narrow enumeration:** HTTPS + ICMP across ~770 hosts, then SMB/RPC/FTP against only the 7–8 that responded. Connection states were 85% S0 (no response, 111,382) and REJ (refused, 101,972) — the signature of scanning, not normal use.

> **Caveat:** the logs show *what* `.50` is doing, not *why*. An authorized vulnerability scanner produces similar traffic. Confirming whether `.50` is a sanctioned asset would be the next investigative step.

> Query file: `queries/06_internal_recon.sql`

---

## Finding 3 — External SSH Brute Force

While internal hosts scanned, external IPs hammered the network. Completed (SF) SSH sessions, ranked by volume with average bytes sent:

| Source IP | Sessions | Avg Bytes | Assessment |
|---|---|---|---|
| 18.191.216.176 | 4,168 | 225 | Automated credential stuffing |
| 218.65.30.30 | 2,875 | 1,659 | Higher-byte brute force tool |
| 58.218.199.133 | 1,519 | 1,370 | Sequential IP pair — coordinated |
| 182.100.67.4 | 1,377 | 1,663 | External brute force |
| 192.168.10.43 | 690 | 1,021 | Infected internal host, also brute-forcing |
| 58.218.199.134 | 84 | 1,290 | Sequential to .133 — same attacker |
| 5.45.85.158 | 62 | 20,114 | ⚠ Massive avg bytes — possible intrusion |
| 5.45.86.133 | 20 | 738,330 | ⚠ Extreme transfer — flag for review |

The sequential `.133`/`.134` pair points to one operator across multiple machines. The infected internal host `.43` appears here too — scanning for telnet victims *and* attempting SSH logins. And `5.45.85.158` stood far outside the brute-force norm on average bytes, demanding a dedicated look.

> Query file: `queries/07_ssh_bruteforce.sql`

---

## Finding 4 — The Intruder Inside (5.45.85.158)

Brute force is noise until one succeeds. Pulling everything `5.45.85.158` did:

| Metric | Value | Meaning |
|---|---|---|
| Target | 192.168.10.43 | Single victim — the Mirai-infected host |
| Sessions | 85 | Sustained access, not a one-off |
| Avg bytes/session | 47,034 | Interactive activity, not guessing |
| Longest session | 11,888s (3h 18m) | Hands-on-keyboard presence |
| Total transferred | ~4.0 MB | Real data movement into the host |

An external IP holding a **3-hour-18-minute session**, moving ~4 MB across 85 sessions into the *same host* running the Mirai scanner — that points to the SSH intrusion as the trigger for `.43`'s compromise (scanning begins 29 minutes later). This is a confirmed intrusion, not a failed attempt. It does *not*, however, explain `.50` or `.60.22`, which the timestamps show were active more than a day earlier — see Finding 6.

> Query file: `queries/08_intruder_deepdive.sql`

---

## Finding 5 — The Network Looked Normal

The simplest query was the most unsettling. Completed sessions by service, while the breach was active:

| Service | Completed Sessions |
|---|---|
| http | 74,614 |
| dns | 33,230 |
| ssl | 30,355 |
| smtp | 9,614 |
| ssh | 7,786 |
| ntp | 234 |

74,000 HTTP sessions completed normally. DNS resolved. Email flowed. From the outside, nothing looked wrong — while two hosts were compromised, an attacker held multi-hour sessions inside, and a third host beaconed to its controllers on a timer.

That gap — between what the traffic looked like and what was happening — is why threat hunting exists. Alerts tell you something fired. Hunting tells you what was already there before anything fired at all.

> Query file: `queries/09_services.sql`

---

## Finding 6 — The Timeline (What Order Did This Happen In?)

The intuitive assumption was that the SSH intrusion was patient zero. Pulling the first-seen time for each activity disproved it:

| Time (UTC) | Event | Host |
|---|---|---|
| May 1, 12:34 | Internal recon begins | `192.168.10.50` — active at capture start |
| May 1, 17:38 | C2 beaconing begins | `192.168.60.22` → 4 external servers |
| **May 2, 16:36** | **SSH intrusion begins (~28h later)** | `5.45.85.158` → `192.168.10.43` |
| **May 2, 17:05** | **Mirai scanning begins (+29 min)** | `192.168.10.43` → 338,181 external IPs |

Internal recon and C2 beaconing were running **more than a day before** the SSH intrusion. The intrusion cleanly explains `.43` — but not `.50` or `.60.22`, which predate it. The network was already compromised before the intrusion visible in these logs.

**Caveat:** these are *first-seen-in-capture* times, not necessarily true patient-zero. An earlier compromise could predate the logged window entirely.

> Query file: `queries/10_timeline.sql`

---

## ISC2 CC Domain Connections

- **Domain 1 (Security Principles):** confidentiality and availability both at risk
- **Domain 4 (Network Security):** lateral movement, unauthorized access, C2 communication
- **Domain 5 (Security Operations):** incident identification, evidence collection, escalation

The `5.45.85.158` finding maps to IR concepts around containment and forensic preservation.

---

## What I'd Do Next

- **Analyze the DNS log.** Cross-reference the 4 C2 IPs from `.60.22` and the `5.45.85.158` sessions against `dns.log` to name the botnet infrastructure.
- **Confirm the status of 192.168.10.50.** Its network-wide sweep is either lateral movement or an authorized scanner — a single asset check resolves which.
- **Trace the earlier compromise.** The timeline shows recon and C2 active before the SSH intrusion in the logs. Earlier captures — or DNS and auth logs from before this window — would help find how `.50` and `.60.22` were first compromised, since the SSH intrusion only explains `.43`.

---

*Every figure in this writeup reproduces against the source `conn.log`. Query files are in `queries/`.*
