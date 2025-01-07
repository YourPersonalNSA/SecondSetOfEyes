from datetime import datetime, timedelta
import json
import os

from gzip import GzipFile
from zstandard import ZstdCompressor, FLUSH_FRAME

from pyroute2.netlink.connector.cn_proc import PROC_EVENT_EXEC
from pyroute2 import ProcEventSocket

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
        fname_zstd = f"procevents/{timestamp}.jsonl.zst"
        fname_gzip = f"procevents/{timestamp}.jsonl.gz"

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

#
# We must run with high priority in order to
# catch short lived lower priority processes
#
# Unless we are root we cannot raise priority
# only lower, and priotity -20 is still unreliable
#
# But if we are root, we can request realtime
# and forkstat does that too:
# https://github.com/ColinIanKing/forkstat/blob/master/forkstat.c
#
def set_priority():
    try:
        os.setpriority(0, 0, -20)
    except PermissionError:
        pass

    print("My priority is", os.getpriority(0, 0))

def set_realtime():
    try:
        max_fifo_prio = os.sched_get_priority_max(os.SCHED_FIFO)
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(max_fifo_prio))
        print("My RT priority is now", max_fifo_prio)
    except PermissionError:
        pass

set_realtime()

ps = ProcEventSocket()
ps.bind()
ps.control(listen=True)

QUOT = "'"
ESC = "\\"

# We should always be able to read cmdline for pids obtained via proc events
# Except when the process is short lived and we're too late to read its info
def read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline") as f:
            args = []

            for x in f.read().split("\0"):
                if ' ' in x or not x:
                    args.append(QUOT + x.replace(QUOT, QUOT + ESC + QUOT + QUOT) + QUOT)
                else:
                    args.append(x)

            args.pop()

            return " ".join(args)
    except FileNotFoundError:
        return "?"

# Sometimes we cannot read where the executable is
# eg. something run with sudo and we are not root
def read_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (FileNotFoundError, PermissionError):
        return "?"

# See: man 5 proc
# See: https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
def find_pty(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            stats = f.read().split(" ")
            device = int(stats[6])
            major = device >> 8
            minor = device & 0xFF

            if major == 136:
                return f"pts/{minor}"

            return "?"
    except FileNotFoundError:
        return "?"

try:
    while True:
        event = ps.get()

        assert len(event) == 1

        if event[0]["what"] == PROC_EVENT_EXEC:
            process_pid = event[0]["process_pid"]
            entry = {
                "time": datetime.now().replace(microsecond=0).astimezone().isoformat(),
                "executable": read_exe(process_pid),
                "cmdline": read_cmdline(process_pid),
                "tty": find_pty(process_pid)
            }

            LogHandler.ensure_schedule()
            handler.handle_event(json.dumps(entry).encode())

            print(json.dumps(entry, indent=2))

except KeyboardInterrupt:
    pass
finally:
    print("Shutting down...")

    ps.close()

    LogHandler.urls_zstd.close()
    LogHandler.urls_gzip.close()
