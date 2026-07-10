-- 08_intruder_deepdive.sql
-- Purpose: Separate a failed brute-forcer from a successful intruder by profiling
--          one source IP's full activity — session count, bytes, and session length.
-- Why it matters: Brute force is noise until one attempt succeeds. A long session
--          moving real data (not tiny credential-guess payloads) is the signature
--          of interactive access — an attacker who got in and stayed.
-- Finding: 5.45.85.158 targeted a SINGLE victim, 192.168.10.43 — the same host
--          running the Mirai scanner. 85 sessions, ~47KB avg, longest session
--          11,888s (3h 18m), ~4.0 MB total. This is a confirmed intrusion and the
--          likely entry point for the whole infection.

SELECT orig_h, resp_h,
       COUNT(*) AS sessions,
       ROUND(AVG(CAST(orig_bytes AS REAL)), 0) AS avg_orig_bytes,
       ROUND(MAX(CAST(duration AS REAL)), 0) AS longest_session_sec,
       ROUND(SUM(CAST(orig_bytes AS REAL)), 0) AS total_bytes
FROM conn_logs
WHERE orig_h = '5.45.85.158'
GROUP BY orig_h, resp_h;

-- Expected output:
-- 5.45.85.158 | 192.168.10.43 | 85 | 47034 | 11888 | 3997881
--   sessions=85 (sustained access, not a one-off)
--   avg_orig_bytes=47034 (interactive activity, not credential-guessing)
--   longest_session=11888s = 3h 18m (hands-on-keyboard presence)
--   total_bytes=3,997,881 ~= 4.0 MB (real data movement into the host)
