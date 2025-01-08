from datetime import datetime, timedelta

import duckdb

today = datetime.now().astimezone().replace(
    hour=0,
    minute=0,
    second=0,
    microsecond=0
)

yesterday = today - timedelta(
    days=1
)

today = today.isoformat()
yesterday = yesterday.isoformat()

x = duckdb.connect()
x.sql(f"create table fsevents as (select * from 'fsevents/*.jsonl.zst' where time between '{yesterday}' and '{today}')")

# Include only items under /home/
# Exclude all dotdirectories but keep all dotfiles
# Ratelimit by way of selecting distinct HH:MM, path pairs
result = x.sql("select distinct strftime(time::TIMESTAMPTZ, '%H:%M'), path from fsevents where type like '%modify%' and path not like '%/.%/%' and path like '/home/%' order by time")

print("Filesystem write events")
print(f"Log opened {yesterday}")

for time, path in result.fetchall():
    print(f"{time} {path}")
