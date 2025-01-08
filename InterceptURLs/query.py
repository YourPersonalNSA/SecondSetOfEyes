from datetime import datetime, timedelta

import duckdb

x = duckdb.connect()
x.sql("create table urls as (select * from 'urls/*.jsonl.zst')")

today = datetime.now().astimezone().replace(
    hour=0,
    minute=0,
    second=0,
    microsecond=0
)

yesterday = today - timedelta(days=1)

today = today.isoformat()
yesterday = yesterday.isoformat()

result = x.sql(f"select strftime(time::TIMESTAMPTZ, '%H:%M'), url, title from urls where time between '{yesterday}' and '{today}'")

print(f"Log opened {yesterday}")

for time, url, title in result.fetchall():
    print(f"{time} {title} {url}")
