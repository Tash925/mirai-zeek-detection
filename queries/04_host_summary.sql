-- 04_host_summary.sql
-- Purpose: One query for the whole story — every host, every red flag
-- Finding: .43 primary threat (17.7% success), .50 confirmed botnet node
--          (0% success), 10.200.200.80 likely third infected host, plus a
--          suspected AWS C2 server at 99.9% success
-- Why it matters: A single briefing-ready table showing attacker, bots,
--                 baseline, and C2 all at once.

SELECT
  orig_h,
  COUNT(*) AS total_connections,
  SUM(CASE WHEN conn_state = 'S0' THEN 1 ELSE 0 END) AS failed_scans,
  SUM(CASE WHEN conn_state = 'SF' THEN 1 ELSE 0 END) AS successful,
  SUM(CASE WHEN proto = 'icmp' THEN 1 ELSE 0 END) AS icmp_recon,
  ROUND(SUM(CASE WHEN conn_state = 'SF' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) AS success_rate_pct
FROM conn_logs
GROUP BY orig_h
ORDER BY total_connections DESC
LIMIT 10;
