
from http.server import HTTPServer, BaseHTTPRequestHandler, HTTPStatus
from datetime import datetime, timedelta

from gzip import GzipFile
from zstandard import ZstdCompressor, FLUSH_FRAME

# Endpoints:
# - Tab API data:
#   /intercept_url           URL and title events
#
# - WebRequest API data: (TODO: implement)
#   /intercept_tx            HTTP requests and request headers
#   /intercept_tx_payload    HTTP request payloads
#   /intercept_rx            HTTP status codes and response headers
#   /intercept_rx_payload    HTTP response payloads
#
# Saving payloads amounts to ~200MB of data per hour of general browsing
#
class InterceptURLHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
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
        fname_zstd = f"urls/{timestamp}.jsonl.zst"
        fname_gzip = f"urls/{timestamp}.jsonl.gz"

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

    # Keep-Alive is enabled
    # Firefox keeps the connection open forever
    def handle(self):
        super().handle()
        print("Disconnected")

    def do_GET(self):
        self.text_response(f"Unknown path [{self.path}]", status=HTTPStatus.NOT_FOUND)

    def do_POST(self):
        length = self.headers.get('content-length')
        payload = self.rfile.read( int(length) )

        if self.path == "/intercept_url":
            self.handle_intercept(payload)
            self.text_response("saved")
        elif self.path.startswith("/intercept_rx_payload/"):
            self.handle_rx_payload(payload, self.path)
            self.text_response("saved")
        else:
            self.text_response(f"Unknown path [{self.path}]", status=HTTPStatus.NOT_FOUND)

    def handle_intercept(self, payload):
        self.ensure_schedule()
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

    def handle_rx_payload(self, payload, path):
        name = path[len("/intercept_rx_payload/"):]

        with open(f"rx_payload/{name}", "wb") as f:
            f.write(payload)

    def text_response(self, text, status=HTTPStatus.OK):
        payload = text.encode()
        self.send_response(status)
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)

InterceptURLHandler.begin_next_file()

def run(server_address):
    httpd = HTTPServer(server_address, InterceptURLHandler)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down...")
        InterceptURLHandler.urls_zstd.close()
        InterceptURLHandler.urls_gzip.close()

run(("127.0.0.1", 8088))
