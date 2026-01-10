from datetime import datetime, timedelta

import duckdb

x = duckdb.connect()
x.sql("create table urls as (select * from 'urls/*.jsonl.zst')")

def query_past(when):
    midnight = datetime.now().astimezone().replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0
    )

    bits = when.split(" ")
    time = bits.pop(0)
    unit = bits.pop(0)

    if "month" in unit:
        since = midnight - timedelta(weeks=4*int(time))
    elif "week" in unit:
        since = midnight - timedelta(weeks=int(time))
    elif "day" in unit:
        since = midnight - timedelta(days=int(time))

    until = since + timedelta(days=1)

    since = since.isoformat()
    until = until.isoformat()

    result = x.sql(f"select strftime(time::TIMESTAMPTZ, '%H:%M'), url, title from urls where time between '{since}' and '{until}'")

    print(f"Log opened {since}")

    for time, url, title in result.fetchall():
        print(f"{time} {title} {url}")
