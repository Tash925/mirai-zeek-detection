# Part 1 — From Raw Log to Botnet Discovery

> How a data analyst found a Mirai botnet in a network log using nothing but SQL.

*Originally published on [DataSec Chronicles](https://datasecchronicles.com). Adapted here as the investigation writeup for this toolkit.*

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

## The full picture — three infected hosts

One infected host is an incident. I wanted to know if it was the only one. So I built a single summary query — every host, total connections, failed scans, successful connections, ICMP recon, and success rate — to profile the whole network at once.

It surfaced more than one problem:

| Host | Total | Success rate | Verdict |
|---|---|---|---|
| 192.168.10.43 | 894,218 | 17.7% | Primary threat actor |
| 192.168.10.50 | 251,368 | 0% | Confirmed botnet node |
| 10.200.200.80 | 40,615 | 4% | Likely third infected host |
| 192.168.61.21 | 24,567 | 94.6% | Normal — baseline host |
| 54.243.185.88 | 10,564 | 99.9% | Suspected C2 server (AWS) |

`.50` completing **zero** connections while generating scans is a dead giveaway of an infected node doing nothing but attacking. `10.200.200.80` sat on a *different subnet* — evidence the infection had already moved laterally across the network, not just spread within one segment. Three infected hosts, at least two subnets, plus a suspected external command-and-control server all fell out of one query.

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
- Mirai port signatures (23, 22, 2323) confirming the malware family
- Three infected hosts across at least two subnets — lateral movement in progress
- A 17.7% vs 94.6% success-rate gap separating infected from clean

That's the core discovery. But every one of these findings raised a sharper question — *how is it being controlled? is it automated? how did it get in?* — and those answers are in [Part 2](part2-c2-brute-force-ssh.md).

---

*Raw data first. Dashboards second.* 🖤
