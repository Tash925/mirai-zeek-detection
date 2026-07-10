-- 07_ssh_bruteforce.sql
-- Purpose: Surface external SSH brute-force activity — hosts making many completed
--          SSH (port 22) sessions, ranked by volume with average bytes sent.
-- Why it matters: Small, repetitive transfers across many sessions are the
--          signature of automated credential-guessing. Outliers in avg bytes
--          (far above the brute-force norm) flag sessions that may have succeeded.
-- Finding: Multiple external IPs attacking simultaneously. The sequential pair
--          58.218.199.133 / .134 indicates one operator across a small block.
--          Infected internal host .43 appears here too. 5.45.85.158 stands far
--          outside the norm on avg bytes (20,114 vs <2,000) — investigated in 08.

SELECT orig_h,
       COUNT(*) AS attempts,
       ROUND(AVG(CAST(orig_bytes AS REAL)), 0) AS avg_bytes_sent
FROM conn_logs
WHERE resp_p = '22'
  AND conn_state = 'SF'
GROUP BY orig_h
ORDER BY attempts DESC
LIMIT 15;

-- Expected output:
-- 18.191.216.176 | 4168 | 225      automated credential stuffing
-- 218.65.30.30   | 2875 | 1659     higher-byte brute force tool
-- 58.218.199.133 | 1519 | 1370     sequential pair - coordinated
-- 182.100.67.4   | 1377 | 1663
-- 192.168.10.43  | 690  | 1021     infected internal host, also brute-forcing
-- 218.92.1.142   | 239  | 1321
-- 61.78.248.54   | 85   | 792
-- 58.218.199.134 | 84   | 1290     sequential to .133 - same attacker
-- 59.63.188.2    | 69   | 1550
-- 5.45.85.158    | 62   | 20114     <- massive avg bytes - possible intrusion
-- 5.45.86.133    | 20   | 738330    <- extreme transfer - flag for review
