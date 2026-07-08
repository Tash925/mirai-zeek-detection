-- 02_failed_connections.sql
-- Purpose: Identify which host is responsible for the S0 flood
-- Finding: 192.168.10.43 — 513,865 S0 connections (79% of all unanswered attempts)
-- Why it matters: One internal host generating this volume isn't a user — it's
--                 an automated, malicious machine scanning the network.

SELECT orig_h, COUNT(*) AS total
FROM conn_logs
WHERE conn_state = 'S0'
GROUP BY orig_h
ORDER BY total DESC
LIMIT 10;
