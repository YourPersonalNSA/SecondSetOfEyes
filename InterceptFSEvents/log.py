
from datetime import datetime, timedelta
import asyncio
import json

from gzip import GzipFile
from zstandard import ZstdCompressor, FLUSH_FRAME

import pyfanotify as fan

class LogHandler():
    last_gzip_tell = 0
    last_zstd_tell = 0
    urls_zstd = None
    urls_gzip = None

    next_file_at = datetime.fromtimestamp(0)

    # Switch to a new file at midnight
    @classmethod
    def reschedule(cls):
        cls.next_file_at = datetime.now().replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        ) + timedelta(days=1)

    @classmethod
    def begin_next_file(cls):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname_zstd = f"fsevents/{timestamp}.jsonl.zst"
        fname_gzip = f"fsevents/{timestamp}.jsonl.gz"

        print("Creating", fname_zstd)
        print("Creating", fname_gzip)

        urls_zstd_fd = open(fname_zstd, "wb")

        # https://python-zstandard.readthedocs.io/en/latest/compressor.html#zstdcompressionwriter
        cctx = ZstdCompressor(level=9)

        cls.urls_zstd = cctx.stream_writer(urls_zstd_fd)
        cls.urls_gzip = GzipFile(fname_gzip, "wb")

        cls.last_zstd_tell = cls.urls_zstd.tell()
        cls.last_gzip_tell = cls.urls_gzip.fileobj.tell()

        cls.reschedule()

    @classmethod
    def ensure_schedule(cls):
        if datetime.now() >= cls.next_file_at:
            cls.urls_zstd.close()
            cls.urls_gzip.close()
            cls.begin_next_file()

    def handle_event(self, payload):
        self.urls_zstd.write(payload)
        self.urls_gzip.write(payload)
        self.flush()

    # We specifically want to keep the file cleanly readable
    # at all points in time - we can sense that zstd stored
    # some bytes to file using tell() and perform a frame
    # flush to ensure it is cleanly readable
    #
    # With gzip we must look at .fileobj.tell()
    #
    def flush(self):
        if self.urls_zstd.tell() != self.last_zstd_tell:
            self.urls_zstd.flush(FLUSH_FRAME)
            self.last_zstd_tell = self.urls_zstd.tell()
            print("Flush zstd")

        if self.urls_gzip.fileobj.tell() != self.last_gzip_tell:
            self.urls_gzip.flush()
            self.last_gzip_tell = self.urls_gzip.fileobj.tell()
            print("Flush gzip")

LogHandler.begin_next_file()
handler = LogHandler()

fanot = fan.Fanotify(init_fid=True)
fanot.mark("/home", is_type="fs", ev_types=fan.FAN_ALL_FID_EVENTS|fan.FAN_ALL_EVENTS)
fanot.start() # Runs in new process

cli = fan.FanotifyClient(fanot, path_pattern="*")

loop = asyncio.new_event_loop()

def handle_events():
    for i in cli.get_events():
        event = {
            "time": datetime.now().replace(microsecond=0).astimezone().isoformat(),
            "type": fan.evt_to_str(i.ev_types),
            "path": i.path[0].decode()
        }

        LogHandler.ensure_schedule()
        handler.handle_event(json.dumps(event).encode())
        print(json.dumps(event, indent=2))

loop.add_reader(cli.sock, handle_events)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass
finally:
    print("Shutting down...")

    cli.close()
    fanot.stop()

    LogHandler.urls_zstd.close()
    LogHandler.urls_gzip.close()
