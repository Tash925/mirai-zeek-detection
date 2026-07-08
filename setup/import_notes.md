\# Setup --- Loading a Zeek conn.log into SQLite

The dataset: \[DNS and Connections Log --- Zeek/Corelight
(Kaggle)\](https://www.kaggle.com/datasets/mimansari/dns-and-connections-log-zeek-or-corelight).

This project uses \*\*conn.log\*\* --- the connection log (1,319,960
records).

\#\# Step 1 --- Strip the Zeek metadata header

Zeek\'s conn.log is not a clean CSV. It opens with metadata lines
starting

with \`\#\`. If you import as-is, those lines load as data rows and your
column

names become timestamps and IP addresses. Strip them first:

\`\`\`bash

grep -v \"\^\#\" conn.log \> conn_clean.csv

\`\`\`

\#\# Step 2 --- Create the table, then import

Define the schema \*before\* loading the data (see \`schema.sql\`). From
the

folder containing \`conn_clean.csv\`, launch SQLite and run:

\`\`\`bash

sqlite3 investigation.db \< schema.sql

\`\`\`

\#\# Step 3 --- Confirm the load

\`\`\`sql

SELECT COUNT(\*) FROM conn_logs;

\-- Expected: 1,319,960

\`\`\`

\> Debugging note: if \`COUNT(\*)\` returns nothing, check you\'re in
the right

\> folder --- a mistyped folder name is the most common cause of a
silent

\> empty result. Learning to debug your environment matters as much as

\> knowing the queries.
