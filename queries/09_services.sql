-- 09_services.sql
-- Purpose: Profile the "normal" completed traffic on the network during the breach.
-- Why it matters: The most unsettling finding is often the quietest one. While two
--          hosts were compromised, an attacker held multi-hour sessions inside, and
--          a third host beaconed to C2 — the everyday services kept running normally.
--          The gap between what traffic LOOKS like and what is HAPPENING is exactly
--          why threat hunting exists: alerts tell you something fired; hunting finds
--          what was already there before anything fired.
-- Note: ssl and dns are the natural next logs to pursue — C2 can hide in encrypted
--       traffic, and the dns.log would resolve the 4 C2 IPs from query 05.

SELECT service, COUNT(*) AS total
FROM conn_logs
WHERE service != '-'
  AND conn_state = 'SF'
GROUP BY service
ORDER BY total DESC
LIMIT 15;

-- Expected output:
-- http | 74614     normal web browsing - users had no idea
-- dns  | 33230     name resolution - cross-reference with C2 IPs next
-- ssl  | 30355     encrypted traffic - C2 can hide here
-- smtp | 9614      email
-- ssh  | 7786      includes the attacker's active sessions
-- ntp  | 234       time sync - normal
