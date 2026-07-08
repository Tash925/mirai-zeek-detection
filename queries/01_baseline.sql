-- 01_baseline.sql
-- Purpose: Take the pulse of the network — count how every connection ended
-- Finding: 647,224 S0 (attempted, no response) — classic scanning. Over 60%
--          of all connections never completed successfully.
-- Why it matters: Failed states (S0, REJ, OTH) far outnumbering SF signals
--                 scanning activity, not normal traffic.

SELECT conn_state, COUNT(*) AS total
FROM conn_logs
GROUP BY conn_state
ORDER BY total DESC;
