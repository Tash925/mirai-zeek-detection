-- 05_c2_beaconing.sql
-- Purpose: Detect command-and-control beaconing — outbound connections from an
--          internal host to external servers at a fixed, machine-regular interval.
-- Finding: 192.168.60.22 beacons to 4 external C2 servers at a ~755-second cadence
--          (coefficient of variation < 0.10 across 216-217 connections each).
-- Why it matters: A tight, repeating interval to a small fixed set of external
--          destinations is the signature of an infected host checking in with C2.
--          The regularity (low CV), not the average interval, is what separates a
--          real beacon from bursty scan traffic that merely averages into range.
--
-- Method notes:
--   * Direction-aware: origin internal (192.168.x), destination external. Beacons
--     are outbound; without this filter, inbound scan traffic gets miscounted.
--   * CV = stddev / mean. Computed without SQRT in the filter by comparing variance
--     directly (var < (0.35*mean)^2) so it runs on sqlite builds lacking SQRT.
--   * conns >= 50 excludes low-volume noise; genuine beaconing produces sustained
--     repeated callbacks over the capture window.

WITH ordered AS (
  SELECT orig_h, resp_h,
         CAST(ts AS REAL) AS t,
         LAG(CAST(ts AS REAL)) OVER (
           PARTITION BY orig_h, resp_h ORDER BY CAST(ts AS REAL)
         ) AS prev_t
  FROM conn_logs
  WHERE orig_h LIKE '192.168.%'
    AND resp_h NOT LIKE '192.168.%'
    AND resp_h NOT LIKE '10.%'
    AND resp_h NOT LIKE '172.1_.%'
    AND resp_h NOT LIKE '17.253.%'   -- exclude Apple time-sync (benign)
),
gaps AS (
  SELECT orig_h, resp_h, (t - prev_t) AS gap
  FROM ordered
  WHERE prev_t IS NOT NULL
),
stats AS (
  SELECT orig_h, resp_h,
         COUNT(*) AS conns,
         AVG(gap) AS mean_gap,
         MAX(0.0, AVG(gap*gap) - AVG(gap)*AVG(gap)) AS var_gap
  FROM gaps
  GROUP BY orig_h, resp_h
)
SELECT orig_h,
       resp_h,
       conns,
       ROUND(mean_gap, 1) AS avg_gap_seconds,
       ROUND(var_gap / (mean_gap*mean_gap), 3) AS cv_squared
FROM stats
WHERE conns >= 50
  AND var_gap < (0.35 * mean_gap) * (0.35 * mean_gap)   -- CV < 0.35
ORDER BY orig_h, cv_squared ASC;

-- Expected output:
-- 192.168.60.22 | 69.43.168.214   | 216 | 757.8 | ~0.004
-- 192.168.60.22 | 109.74.9.119    | 217 | 754.5 | ~0.008
-- 192.168.60.22 | 192.188.58.163  | 217 | 754.3 | ~0.008
-- 192.168.60.22 | 203.153.165.21  | 217 | 754.2 | ~0.008
