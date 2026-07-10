-- 06_internal_recon.sql
-- Purpose: Detect internal reconnaissance / lateral-movement staging — an internal
--          host sweeping other internal hosts to map live machines and services.
-- Finding: 192.168.10.50 contacted 771 distinct internal hosts across 251,368
--          connections (all but 3 internal). Two-phase pattern:
--            Phase 1 - broad discovery: HTTPS (443) + ICMP sweeps across ~770 hosts
--            Phase 2 - targeted enumeration: SMB(445)/RPC(135)/NetBIOS(139)/FTP(21)
--                      against only 7-8 specific hosts (those that responded)
--          85% of its connections were S0 (no response) or REJ (refused) — the
--          signature of scanning, not normal use. Success rate: ~0.5%.
-- Why it matters: Where the Mirai scanner (.43) pointed OUTWARD at the internet,
--          this host points INWARD. Broad-sweep-then-narrow-probe is a classic
--          reconnaissance shape: find what's alive, then enumerate the responders.
--
-- Caveat: Logs show WHAT .50 is doing, not WHY. An authorized vulnerability
--         scanner produces similar traffic. Next step in a real environment:
--         confirm whether .50 is a known, sanctioned asset before escalating.

-- Query A: direction — is this host scanning internally or externally?
SELECT
  CASE WHEN resp_h LIKE '192.168.%' THEN 'internal' ELSE 'external' END AS target_type,
  COUNT(*) AS conns,
  COUNT(DISTINCT resp_h) AS distinct_targets
FROM conn_logs
WHERE orig_h = '192.168.10.50'
GROUP BY target_type;
-- Expected: internal | 251365 | 771   /   external | 3 | 2

-- Query B: activity breakdown by port/proto — the two-phase pattern
SELECT resp_p, proto, service,
       COUNT(*) AS conns,
       COUNT(DISTINCT resp_h) AS targets
FROM conn_logs
WHERE orig_h = '192.168.10.50'
GROUP BY resp_p, proto, service
ORDER BY conns DESC
LIMIT 12;
-- Expected (top rows):
--   443  | tcp  | -   | 51686 | 768   <- broad HTTPS sweep
--   14   | icmp | -   | 18573 | 763   <- ICMP timestamp sweep
--   0    | icmp | -   | 18060 | 769   <- ICMP echo sweep
--   445  | tcp  | -   | 3439  | 8     <- narrow SMB enumeration
--   21/135/139 ...    | 7 targets each <- targeted service probes

-- Query C: connection-state breakdown — confirms scanning failure pattern
SELECT conn_state, COUNT(*) AS conns
FROM conn_logs
WHERE orig_h = '192.168.10.50'
GROUP BY conn_state
ORDER BY conns DESC;
-- Expected: S0 111382 | REJ 101972 | OTH 36633 | RSTO 1381  (~85% S0+REJ)
