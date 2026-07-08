-- schema.sql
-- Create the conn_logs table BEFORE importing (schemas are defined before data loads).
-- Column names follow Zeek conn.log field order so the tab-separated import lines up.

CREATE TABLE conn_logs (
  ts TEXT, uid TEXT, orig_h TEXT, orig_p TEXT,
  resp_h TEXT, resp_p TEXT, proto TEXT, service TEXT,
  duration TEXT, orig_bytes TEXT, resp_bytes TEXT,
  conn_state TEXT, local_orig TEXT, local_resp TEXT,
  missed_bytes TEXT, history TEXT, orig_pkts TEXT,
  orig_ip_bytes TEXT, resp_pkts TEXT, resp_ip_bytes TEXT,
  tunnel_parents TEXT
);

-- Zeek conn.log is tab-separated. Set the import mode to tabs, then load the
-- header-stripped file (see import_notes.md for how conn_clean.csv is produced).
.mode tabs
.import conn_clean.csv conn_logs
