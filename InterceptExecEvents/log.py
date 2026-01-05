from datetime import datetime, timedelta
import asyncio
import json

from gzip import GzipFile
from zstandard import ZstdCompressor, FLUSH_FRAME

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

# https://github.com/bpftrace/bpftrace/blob/master/tools/execsnoop.bt
# https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_exec
# https://mozillazg.com/2024/03/ebpf-tracepoint-syscalls-sys-enter-execve-can-not-get-filename-argv-values-case-en.html
#

async def read_events_syscall(handler):
    proc = await asyncio.create_subprocess_exec(
        "bpftrace",
        "-e",
        """
        // With programs that spawn other programs, esp. `make -j`
        // a lot of sys_enter_exec* may occur before
        // any sys_exit_exec*

        // Keep in mind: with join(), argv is truncated to 16 arguments
        // we use own loop over argv instead
        tracepoint:syscalls:sys_enter_exec* {
            printf(
                "ENTER\\0%s\\0%s\\0%d\\0",
                strftime("%Y-%m-%dT%H:%M:%S%z", nsecs),
                comm,
                pid
            );

            $i = 0;

            while ($i < 4096) {
                if ( (uint64)*(args->argv+$i) == 0 ) { break; }
                printf("%s ", str(*(args->argv+$i)));
                $i++
            }

            printf("\\n");
        }

        tracepoint:syscalls:sys_exit_exec* {
            printf(\"LEAVE\\0%d\\0%d\\0\", pid, args->ret);
        }
        """,
        stdout=asyncio.subprocess.PIPE
    )


    assert await proc.stdout.readline() == b"Attaching 4 probes...\n"

    posted = {}
    solved = {}

    # A little flimsy, this loop
    # It functions despite preemption because of printf buffering
    while True:
        head = await proc.stdout.readuntil(b"\0")

        if head == b"ENTER\0":
            time = await proc.stdout.readuntil(b"\0")
            comm = await proc.stdout.readuntil(b"\0")
            pida = await proc.stdout.readuntil(b"\0")
            argv = await proc.stdout.readuntil(b"\n")

            time = time[:-1]
            comm = comm[:-1]
            pida = pida[:-1]
            argv = argv[:-1]

            assert pida not in posted

            posted[pida] = dict(
                time=time,
                comm=comm,
                argv=argv
            )

            pid = pida
        elif head == b"LEAVE\0":
            pidb = await proc.stdout.readuntil(b"\0")
            retv = await proc.stdout.readuntil(b"\0")

            pidb = pidb[:-1]
            retv = retv[:-1]

            assert pidb not in solved

            solved[pidb] = dict(
                retv=retv
            )

            pid = pidb
        else:
            assert 0, f"Protocol break: {head}"

        if pid in posted and pid in solved:
            retv = solved[pid]["retv"]
            time = posted[pid]["time"]
            comm = posted[pid]["comm"]
            argv = posted[pid]["argv"]

            if retv == b"0":
                entry = dict(
                    time=time.decode(),
                    comm=comm.decode(),
                    argv=argv.decode()
                )

                handler.ensure_schedule()
                handler.handle_event(json.dumps(entry).encode())

                print(json.dumps(entry, indent=2))

            del posted[pid]
            del solved[pid]

# Alternative version that is unused at the present
# May work on systems that lack syscall tracepoints
async def read_events_sched():
    proc = await asyncio.create_subprocess_exec(
        "bpftrace",
        "-B",
        "none",
        "-e",
        """
        #include <linux/sched.h>
        #include <linux/mm_types.h>

        // This tracepoint is distinct from tracepoint:syscalls:sys_enter_exec*;
        // we only see successful execs here rather than all attempted
        tracepoint:sched:sched_process_exec {
            $task=curtask;
            $arg_start=$task->mm->arg_start;
            $arg_end=$task->mm->arg_end;
            $count = $arg_end-$arg_start;

            printf(\"%s\\0\", strftime("%Y-%m-%dT%H:%M:%S%z", nsecs));
            printf(\"%s\\0\", comm);

            // We have to get creative to print large buffers
            // buf() is limited to 64 bytes by default
            $i = (uint64)0;

            while ($i < 4096) {
                if ($count > $i) {
                    printf(\"%r\", buf(uptr($arg_start + $i), $count - $i));
                }

                $i += 64;
            }

            printf(\"\\0\");
        }
        """,
        stdout=asyncio.subprocess.PIPE
    )

    assert await proc.stdout.readline() == b"Attaching 1 probe...\n"

    while True:
        time = await proc.stdout.readuntil(b"\0")
        comm = await proc.stdout.readuntil(b"\0")
        argv = await proc.stdout.readuntil(b"\0")

        time = time[:-1]
        comm = comm[:-1]
        argv = argv[:-1]

        print(time, comm, argv)

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
