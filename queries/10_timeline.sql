-- 10_timeline.sql
-- Purpose: Reconstruct the incident chronology — the first- and last-seen time of
--          each malicious activity — to establish what happened in what order.
-- Why it matters: The intuitive assumption was that the SSH intrusion was patient
--          zero. The timestamps disproved it: internal recon and C2 beaconing were
--          already active ~28 hours BEFORE the SSH intrusion. The intrusion cleanly
--          explains .43 (scanning starts 29 min later) but not .50 or .60.22, which
--          predate it. The network was already compromised when the capture began.
--
-- Note: ts is stored as text (Unix epoch seconds). datetime(...,'unixepoch') makes
--       it readable. These are FIRST-SEEN-IN-CAPTURE times, not necessarily true
--       patient-zero — an earlier compromise could predate the logged window.

-- SSH intrusion window (5.45.85.158 -> .43)
SELECT '1. SSH intrusion' AS event,
       datetime(MIN(CAST(ts AS REAL)),'unixepoch') AS first_seen,
       datetime(MAX(CAST(ts AS REAL)),'unixepoch') AS last_seen
FROM conn_logs WHERE orig_h='5.45.85.158';

-- .43 external scanning window (Mirai propagation, telnet-family ports)
SELECT '2. .43 scanning' AS event,
       datetime(MIN(CAST(ts AS REAL)),'unixepoch') AS first_seen,
       datetime(MAX(CAST(ts AS REAL)),'unixepoch') AS last_seen
FROM conn_logs
WHERE orig_h='192.168.10.43' AND resp_p IN ('23','2323','2222')
  AND resp_h NOT LIKE '192.168.%';

-- .50 internal recon window
SELECT '3. .50 internal recon' AS event,
       datetime(MIN(CAST(ts AS REAL)),'unixepoch') AS first_seen,
       datetime(MAX(CAST(ts AS REAL)),'unixepoch') AS last_seen
FROM conn_logs WHERE orig_h='192.168.10.50' AND resp_h LIKE '192.168.%';

-- .60.22 C2 beaconing window
SELECT '4. .60.22 C2 beaconing' AS event,
       datetime(MIN(CAST(ts AS REAL)),'unixepoch') AS first_seen,
       datetime(MAX(CAST(ts AS REAL)),'unixepoch') AS last_seen
FROM conn_logs WHERE orig_h='192.168.60.22'
  AND resp_h IN ('69.43.168.214','109.74.9.119','192.188.58.163','203.153.165.21');

-- Confirmed chronology (UTC), sorted by first-seen:
--   2019-05-01 12:34:54   .50 internal recon begins   (earliest — capture start)
--   2019-05-01 17:38:41   .60.22 C2 beaconing begins  (+5h)
--   2019-05-02 16:36:57   SSH intrusion begins        (+28h)
--   2019-05-02 17:05:58   .43 scanning begins         (+29 min after intrusion)
-- Total incident span in capture: ~50.7 hours (~2.1 days)
