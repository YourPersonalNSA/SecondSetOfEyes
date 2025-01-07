from datetime import datetime, timedelta

import duckdb

yesterday = (datetime.now().astimezone().replace(
    hour=0,
    minute=0,
    second=0,
    microsecond=0
) - timedelta(
    days=1
)).isoformat()

x = duckdb.connect()
x.sql(f"create table procevents as (select * from 'procevents/*.jsonl.zst' where time >= '{yesterday}')")

# query_a: compute number of events for each time+executable pair - time is of 1s resolution
# query_b: generate id for order retention
# query_c: annotate events for ratelimiting
query_a = "create table ratelimit as select time, executable, count(*) as rlim from procevents group by time, executable"
query_b = "create table procevents2 as select row_number() over () as id, * from procevents"
query_c = "select strftime(u.time::TIMESTAMPTZ, '%H:%M') as time, u.executable, u.cmdline, v.rlim "\
          "from procevents2 u inner join ratelimit v on u.time=v.time and u.executable=v.executable "\
          "order by id"

result = x.sql(query_a)
result = x.sql(query_b)
result = x.sql(query_c)

print("Process exec events")
print(f"Log opened {yesterday}")

# ratelimited time+executable pairs go here
skiplist = {}

for time, executable, cmdline, rlim in result.fetchall():
    if (time, executable) in skiplist:
        continue

    if rlim > 3:
        print(f"{time} <{rlim} invocations of {executable}>")
        skiplist[(time, executable)] = 1
    else:
        print(f"{time} {cmdline}")
