-- 03_port_signatures.sql
-- Purpose: Identify which ports host .43 was scanning to name the threat
-- Finding: Heavy scanning on 23 (Telnet, 157K), 22 (SSH, 124K), and 2323
--          (alt Telnet, 17K) — the classic Mirai signature
-- Why it matters: Port targeting turns "unknown scanning" into a named,
--                 known threat: the Mirai botnet.

SELECT resp_p, COUNT(*) AS attempts
FROM conn_logs
WHERE orig_h = '192.168.10.43'
AND conn_state = 'S0'
GROUP BY resp_p
ORDER BY attempts DESC
LIMIT 10;
