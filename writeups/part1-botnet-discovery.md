# Part 1 — From Raw Log to Botnet Discovery

> How a data analyst found a Mirai botnet in a network log using nothing but SQL.

*Originally published on [DataSec Chronicles](https://datasecchronicles.com). Adapted here as the investigation writeup for this toolkit.*

> **Updated:** After the deeper analysis in Part 2, I revisited the host classifications below and tightened them to what the data strictly supports. The core discovery — a Mirai-infected host mass-scanning from inside the network — is unchanged. What I refined: some hosts I'd initially grouped as "infected" turned out to be doing different things (internal reconnaissance, HTTP traffic), and one I'd flagged as a possible C2 server doesn't fit that role. Re-auditing your own findings is the job; I'm leaving the correction visible rather than quietly swapping numbers.

---

## The starting point

No SIEM. No dashboard. No pre-built alerts. Just a raw Zeek `conn.log` sitting on my Mac and a question I've asked a thousand times in a thousand datasets: *what in here looks wrong?*

I've spent a decade as a data analyst. The tools of cybersecurity were new to me, but the instinct — knowing what normal looks like so abnormal jumps out — was not. This is the story of pointing that instinct at a network log for the first time.

## Getting the data in (the unglamorous part)

Loading a Zeek log into SQLite isn't a clean one-liner. Zeek's `conn.log` ships with metadata header lines that break a straight import, so the first real task was stripping those with `grep` before defining a schema and loading the rows. I hit the usual friction — wrong folder, schema-before-import ordering — and I'm leaving that in, because that friction is the job. (Full steps are in [`setup/import_notes.md`](../setup/import_notes.md).)

## Establishing baseline

Before you can spot the outlier, you have to know what ordinary traffic looks like. I queried connection-state distribution across the whole dataset — 1,319,960 records — to get a feel for normal. The result was already telling: 647,224 connections were S0 (attempted, no response), and over 60% never completed successfully. A healthy network doesn't look like that. This was the network-wide fingerprint of mass scanning.

## The moment it flagged

I narrowed to **S0 connections** — attempts that got no response — grouped by source host. One host stood apart from everything else:

**`192.168.10.43` was responsible for 513,865 S0 connections — 79% of every unanswered attempt in the dataset.**

In analytics terms, that's not an outlier, that's a different distribution entirely. A host generating half a million dead connections isn't browsing — it's scanning. And mass scanning from an internal host is exactly how a botnet spreads.

## Confirming Mirai

Scanning behavior narrows the suspects. To name the malware, I looked at which ports `.43` was targeting. The pattern was textbook: heavy scanning on **23 (Telnet), 22 (SSH), and 2323 (alt-Telnet)**. That's the Mirai signature. Mirai spreads by hammering Telnet and SSH on IoT devices still running factory-default credentials, and those alternate ports are its calling card.

At that point this stopped being a hypothesis and became an identification.

## The full picture — more than one anomalous host

One infected host is an incident. I wanted to know if it was the only one. So I built a single summary query — every host, total connections, failed scans, successful connections, and success rate — to profile the whole network at once.

It surfaced several hosts worth a closer look:

| Host | Total | Success rate | What the data shows |
|---|---|---|---|
| 192.168.10.43 | 894,218 | 17.7% | Confirmed Mirai scanner — telnet-family ports, primary threat |
| 192.168.10.50 | 251,368 | ~0% | Heavy scanning, but HTTPS/ICMP — internal recon, not Mirai (see Part 2) |
| 10.200.200.80 | 40,615 | 4% | External scanner — HTTPS/ICMP/DNS discovery, not telnet; role unconfirmed |
| 54.243.185.88 | 10,564 | 99.9% | High-volume outbound HTTP — likely a normal client, not a threat |
| 192.168.61.21 | 24,567 | 94.6% | Normal — baseline host |

Only `.43` fits the Mirai signature cleanly — it's the one hammering telnet-family ports at scale, and it's the confirmed infection. The others are more nuanced than my first pass assumed: `.50` is scanning too, but on HTTPS and ICMP rather than telnet, which reads as internal reconnaissance (Part 2 digs into this). `10.200.200.80` is also sweeping, but again not on Mirai's ports — so "scanner," yes; "Mirai node," not established. And `54.243.185.88`, which I'd initially eyed as a possible C2 server, turns out to only *originate* connections — almost all outbound HTTP — which is the opposite of what a C2 server looks like. It's most likely a normal high-volume client.

The honest takeaway from this query: **one confirmed Mirai infection (`.43`), plus additional anomalous scanning hosts whose exact roles need the deeper analysis in Part 2.** The instinct to check for more than one problem was right — but naming each host's role required more than a single success-rate number.

## The closing number

The most shareable result was the simplest comparison — the infected primary host next to a clean one:

| Host | Connection success rate |
|---|---|
| Infected (`192.168.10.43`) | **17.7%** |
| Clean host (`192.168.61.21`) | **94.6%** |

That gap tells the whole story in two numbers. A healthy host completes almost everything it starts. An infected host is throwing connections into the void, over and over, looking for the next victim.

## What Part 1 established

- A network-wide scanning fingerprint: 647,224 S0 connections, 60%+ never completing
- A primary infected host (`.43`) responsible for 79% of all failed attempts
- Mirai port signatures (23, 22, 2323) on `.43` confirming the malware family
- Additional anomalous scanning hosts (`.50`, `10.200.200.80`) whose roles Part 2 investigates
- A 17.7% vs 94.6% success-rate gap separating the infected host from a clean one

That's the core discovery. But every one of these findings raised a sharper question — *how is it being controlled? is it automated? how did it get in? and what exactly are those other scanning hosts doing?* — and those answers are in [Part 2](part2-c2-brute-force-ssh.md).

---

*Raw data first. Dashboards second.* 🖤
