from datetime import datetime, timedelta
import asyncio
import json

from gzip import GzipFile
from zstandard import ZstdCompressor, FLUSH_BLOCK

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
        fname_zstd = f"execevents/{timestamp}.jsonl.zst"
        fname_gzip = f"execevents/{timestamp}.jsonl.gz"

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
    # some bytes to file using tell() and perform a flush
    # to ensure it is cleanly readable
    #
    # The decoder may complain to stderr but the data
    # should remain valid
    #
    # With gzip we must look at .fileobj.tell()
    #
    def flush(self):
        if self.urls_zstd.tell() != self.last_zstd_tell:
            self.urls_zstd.flush(FLUSH_BLOCK)
            self.last_zstd_tell = self.urls_zstd.tell()
            print("Flush zstd")

        if self.urls_gzip.fileobj.tell() != self.last_gzip_tell:
            self.urls_gzip.flush()
            self.last_gzip_tell = self.urls_gzip.fileobj.tell()
            print("Flush gzip")

# https://github.com/bpftrace/bpftrace/blob/master/tools/execsnoop.bt
# https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_exec
# https://stackoverflow.com/questions/55457370/how-to-avoid-valueerror-separator-is-not-found-and-chunk-exceed-the-limit
# https://mozillazg.com/2024/03/ebpf-tracepoint-syscalls-sys-enter-execve-can-not-get-filename-argv-values-case-en.html
#

# Executable invocation event tracer
#
# With programs that spawn other programs, esp. `make -j`, a lot
# of sys_enter_exec* may occur before any sys_exit_exec*, so we
# must keep track of issued/resolved syscalls
#
async def read_events_syscall(handler):
    proc = await asyncio.create_subprocess_exec(
        "bpftrace",
        "-e",
        """
        #include <linux/sched.h>
        #include <linux/mm_types.h>

        // We may look at args->argv, but:
        // - with join(), argv is truncated to 16 arguments
        // - with own loop over argv, args are truncated to 64 bytes
        //
        // We look at curtask->mm->arg_start instead
        //
        tracepoint:syscalls:sys_enter_exec* {
            $task=curtask;
            $arg_start=$task->mm->arg_start;
            $arg_end=$task->mm->arg_end;
            $count = $arg_end-$arg_start;

            // We have to get creative to print large buffers
            // buf() is limited to 64 bytes by default
            $i = (uint64)0;

            // We loop in a slightly roundabout way to avoid
            // a dynamic buf size as best we can
            //
            // dynamic buf size upsets the verifier, causing
            // excessive branching
            while ($i < 131072) {
                if ($i + 64 > $count) { break; }

                printf("%r", buf(uptr($arg_start + $i), 64));

                $i += 64;
            }

            // Final print
            printf("%r\\0ENTER\\0%s\\0%s\\0%p\\0%d\\n",
                buf(uptr($arg_start + $i), $count - $i),
                strftime("%Y-%m-%dT%H:%M:%S%z", nsecs),
                comm,
                curtask, pid
            );
        }

        tracepoint:syscalls:sys_exit_exec* {
            $task=curtask;
            $arg_start=$task->mm->arg_start;
            $arg_end=$task->mm->arg_end;
            $count = $arg_end-$arg_start;

            $i = (uint64)0;

            while ($i < 131072) {
                if ($i + 64 > $count) { break; }
                printf("%r", buf(uptr($arg_start + $i), 64));
                $i += 64;
            }

            printf("%r\\0LEAVE\\0%p\\0%d\\0%d\\n",
                buf(uptr($arg_start + $i), $count - $i),
                curtask, pid,
                args->ret
            );
        }
        """,
        stdout=asyncio.subprocess.PIPE,
        limit=3*1024*1024
    )


    assert await proc.stdout.readline() == b"Attaching 4 probes...\n"

    print("Ready")

    posted = {}
    solved = {}

    # A little flimsy, this wire protocol
    # Some printf trampling may occur under high concurrency (it will crash)
    while True:
        argv = await proc.stdout.readuntil(b"\0")
        head = await proc.stdout.readuntil(b"\0")

        if head == b"ENTER\0":
            time = await proc.stdout.readuntil(b"\0")
            comm = await proc.stdout.readuntil(b"\0")
            task = await proc.stdout.readuntil(b"\0")
            pida = await proc.stdout.readuntil(b"\n")

            time = time[:-1]
            comm = comm[:-1]
            pida = pida[:-1]
            argv = argv[:-1]

            key = (task, pida)

            assert key not in posted

            posted[key] = dict(
                time=time,
                comm=comm,
                argv=argv,
            )

            pid = pida
        elif head == b"LEAVE\0":
            task = await proc.stdout.readuntil(b"\0")
            pidb = await proc.stdout.readuntil(b"\0")
            retv = await proc.stdout.readuntil(b"\n")

            pidb = pidb[:-1]
            retv = retv[:-1]
            argv = argv[:-1]

            key = (task, pidb)

            assert key not in solved

            solved[key] = dict(
                retv=retv,
                argv=argv
            )

            pid = pidb
        else:
            assert 0, f"Protocol break: {head}"

        if key in posted and key in solved:
            retv = solved[key]["retv"]
            time = posted[key]["time"]
            comm = posted[key]["comm"]
            argx = posted[key]["argv"]
            argy = solved[key]["argv"]

            del posted[key]
            del solved[key]

            if retv == b"0":
                entry = dict(
                    time=time.decode(),
                    comm=comm.decode(),
                    argx=argx.decode("unicode_escape").split("\0"),
                    argy=argy.decode("unicode_escape").split("\0")
                )

                handler.ensure_schedule()
                handler.handle_event(json.dumps(entry).encode())

                print(json.dumps(entry, indent=2))
            else:
                assert argx == argy

# Alternative version that is unused at the present
# May work on systems that lack syscall tracepoints
async def read_events_sched(handler):
    proc = await asyncio.create_subprocess_exec(
        "bpftrace",
        "-B",
        "none",
        "-e",
        """
        // This tracepoint is distinct from tracepoint:syscalls:sys_enter_exec*;
        // we only see successful execs here rather than all attempted
        //
        // This codepath targets kernel 4.19 which is somewhat busted:
        // we cannot seem to read any memory there, and resort to
        // reading procfs
        //
        // For short lived processes there will be no output,
        // as failing cat() aborts
        //
        tracepoint:sched:sched_process_exec {
            cat("/proc/%d/cmdline", pid);

            printf("\\0%s\\0", strftime("%Y-%m-%dT%H:%M:%S%z", nsecs));
        }
        """,
        stdout=asyncio.subprocess.PIPE,
        limit=3*1024*1024
    )

    assert await proc.stdout.readline() == b"Attaching 1 probe...\n"

    while True:
        argv = await proc.stdout.readuntil(b"\0\0")
        time = await proc.stdout.readuntil(b"\0")

        time = time[:-1]
        argv = argv[:-1]

        entry = dict(
            time=time.decode(),
            comm="",
            argx="",
            argy=argv.decode().split("\0")
        )

        handler.ensure_schedule()
        handler.handle_event(json.dumps(entry).encode())

        print(json.dumps(entry, indent=2))


LogHandler.begin_next_file()
handler = LogHandler()

try:
    asyncio.run(read_events_syscall(handler))
except KeyboardInterrupt:
    pass
finally:
    print("Shutting down...")

    LogHandler.urls_zstd.close()
    LogHandler.urls_gzip.close()
