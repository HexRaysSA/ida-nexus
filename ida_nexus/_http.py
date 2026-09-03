import hmac
import queue
import socket
import threading
import time
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BufferedIOBase
from urllib.parse import urlsplit

from ._serialization import dumps_json

HOST = "127.0.0.1"
POST_BODY_LIMIT = 4 * 1024 * 1024
MAX_CHUNK_LINE = 8192
MAX_TRAILER_BYTES = 64 * 1024
_HTTP_TOKEN_BYTES = (
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
PREWARM_HANDLER_THREADS = 4
MAX_IDLE_HANDLER_THREADS = 8
ServerRequest = socket.socket | tuple[bytes, socket.socket]


@dataclass
class HTTPResponse:
    status: int
    body: bytes = b""
    content_type: str = "application/json"
    headers: Mapping[str, str] = field(default_factory=dict)
    after_send: Callable[[], None] | None = None
    stream: Callable[[BufferedIOBase], None] | None = None


def json_response(
    status: int,
    payload: object,
    *,
    headers: Mapping[str, str] | None = None,
    after_send: Callable[[], None] | None = None,
) -> HTTPResponse:
    return HTTPResponse(
        status=status,
        body=dumps_json(payload).encode("utf-8") + b"\n",
        headers=headers or {},
        after_send=after_send,
    )


class RequestHandler(BaseHTTPRequestHandler):
    """Authenticated HTTP/1.1 handler with bounded request decoding."""

    server: "LocalHTTPServer"  # pyright: ignore[reportIncompatibleVariableOverride]
    server_version = "ida-nexus/0.10.0"  # NOTE: we cannot use importlib.metadata because ida-nexus is not a package in IDA
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30
    disable_nagle_algorithm = True

    def handle(self) -> None:
        try:
            super().handle()
        except (
            ConnectionAbortedError,
            ConnectionResetError,
            BrokenPipeError,
            TimeoutError,
        ):
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _request_body_framing(self) -> tuple[bool, int] | None:
        transfer_values = self.headers.get_all("Transfer-Encoding", [])
        length_values = self.headers.get_all("Content-Length", [])

        if transfer_values and length_values:
            self.close_connection = True
            self.send_error(400, "Conflicting request framing")
            return None

        if transfer_values:
            encodings = [
                item.strip().lower()
                for value in transfer_values
                for item in value.split(",")
                if item.strip()
            ]
            if encodings != ["chunked"]:
                self.close_connection = True
                self.send_error(400, "Unsupported Transfer-Encoding")
                return None
            return True, 0

        if len(length_values) > 1:
            self.close_connection = True
            self.send_error(400, "Ambiguous Content-Length")
            return None
        if not length_values:
            return False, 0

        length_text = length_values[0].strip(" \t")
        if not length_text or any(char not in "0123456789" for char in length_text):
            self.close_connection = True
            self.send_error(400, "Invalid Content-Length")
            return None

        normalized_length = length_text.lstrip("0") or "0"
        limit_text = str(POST_BODY_LIMIT)
        if len(normalized_length) > len(limit_text) or (
            len(normalized_length) == len(limit_text) and normalized_length > limit_text
        ):
            self._send_payload_too_large()
            return None
        return False, int(normalized_length)

    def handle_expect_100(self) -> bool:
        # BaseHTTPRequestHandler would otherwise accept the body before auth
        # or before rejecting deterministically invalid request framing.
        if not self._check_api_request():
            return False
        framing = self._request_body_framing()
        if framing is None:
            return False
        chunked, content_length = framing
        if self.command != "POST" and (chunked or content_length):
            self.send_error(400, "Request body is not allowed")
            return False
        self.send_response_only(100)
        self.end_headers()
        return True

    def _respond(self, response: HTTPResponse) -> None:
        try:
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            if response.stream is None:
                self.send_header("Content-Length", str(len(response.body)))
            else:
                # A lease stream owns this connection until it disconnects.
                self.close_connection = True
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.close_connection and response.stream is None:
                self.send_header("Connection", "close")
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                if response.stream is not None:
                    response.stream(self.wfile)
                elif response.body:
                    self.wfile.write(response.body)
                    self.wfile.flush()
        except (
            BrokenPipeError,
            ConnectionResetError,
            ConnectionAbortedError,
            TimeoutError,
        ):
            pass
        finally:
            # Lease accounting must finish even if the peer disconnects while
            # headers or stream data are being sent.
            if response.after_send is not None:
                response.after_send()

    def _send_json(
        self,
        status: int,
        payload: object,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._respond(json_response(status, payload, headers=headers))

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        self._send_json(code, {"ok": False, "error": message or "error"})

    def _check_api_request(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        host_required = self.request_version not in ("HTTP/0.9", "HTTP/1.0")
        if (
            len(hosts) > 1
            or (host_required and not hosts)
            or (hosts and hosts[0] not in self.server.allowed_hosts)
        ):
            self.close_connection = True
            self.send_error(403, "Forbidden")
            return False

        # Browser JavaScript cannot suppress or forge these headers.
        if "Origin" in self.headers or "Sec-Fetch-Site" in self.headers:
            self.close_connection = True
            self.send_error(403, "Forbidden")
            return False

        authorizations = self.headers.get_all("Authorization", [])
        supplied = authorizations[0] if len(authorizations) == 1 else ""
        expected = f"Bearer {self.server.token}"
        if not hmac.compare_digest(supplied, expected):
            self.close_connection = True
            self._send_json(
                401,
                {"status": "unauthorized"},
                headers={"WWW-Authenticate": "Bearer"},
            )
            return False
        return True

    def _dispatch(self, method: str, body: bytes | None = None) -> None:
        target = urlsplit(self.path)
        try:
            response = self.server.application(method, target.path, target.query, body)
        except Exception:  # noqa: BLE001 -- application is an isolation boundary
            # Application dispatch should normally convert its own failures.
            response = json_response(
                500, {"ok": False, "error": "Internal Server Error"}
            )
        self._respond(response)

    def _has_unexpected_body(self) -> bool:
        if self.headers.get_all("Transfer-Encoding", []):
            return True
        length_values = self.headers.get_all("Content-Length", [])
        if not length_values:
            return False
        if len(length_values) != 1:
            return True
        length_text = length_values[0].strip(" \t")
        if not length_text or any(char not in "0123456789" for char in length_text):
            return True
        return any(char != "0" for char in length_text)

    def do_GET(self) -> None:
        if self._check_api_request():
            if self._has_unexpected_body():
                self.close_connection = True
                self.send_error(400, "Request body is not allowed")
                return
            self._dispatch("GET")

    def do_HEAD(self) -> None:
        if self._check_api_request():
            if self._has_unexpected_body():
                self.close_connection = True
                self.send_error(400, "Request body is not allowed")
                return
            self._dispatch("GET")

    def do_POST(self) -> None:
        if not self._check_api_request():
            return
        body = self._read_body()
        if body is not None:
            self._dispatch("POST", body)

    def _reject_other(self) -> None:
        if self._check_api_request():
            self.close_connection = True
            self.send_error(404, "Not Found")

    do_OPTIONS = _reject_other
    do_PUT = _reject_other
    do_DELETE = _reject_other
    do_PATCH = _reject_other
    do_TRACE = _reject_other
    do_CONNECT = _reject_other

    def _read_body(self) -> bytes | None:
        framing = self._request_body_framing()
        if framing is None:
            return None
        chunked, content_length = framing

        if chunked:
            raw = self._read_chunked()
            if raw is None:
                return None
        else:
            raw = self.rfile.read(content_length) if content_length else b""
            if len(raw) != content_length:
                self.close_connection = True
                self.send_error(400, "Truncated request body")
                return None
        return self._decompress_body(raw)

    def _send_payload_too_large(self) -> None:
        self.close_connection = True
        self.send_error(413, f"Payload exceeds {POST_BODY_LIMIT} bytes")

    def _readline_bounded(self, limit: int, error_message: str) -> bytes | None:
        line = self.rfile.readline(limit + 1)
        if len(line) > limit or not line.endswith(b"\n"):
            self.close_connection = True
            self.send_error(400, error_message)
            return None
        return line

    def _read_chunked(self) -> bytes | None:
        chunks: list[bytes] = []
        total = 0
        while True:
            line = self._readline_bounded(MAX_CHUNK_LINE, "Malformed chunked encoding")
            if line is None:
                return None
            size_text = line.split(b";", 1)[0].strip()
            if not size_text or any(
                byte not in b"0123456789abcdefABCDEF" for byte in size_text
            ):
                self.close_connection = True
                self.send_error(400, "Malformed chunked encoding")
                return None
            chunk_size = int(size_text, 16)
            if chunk_size == 0:
                trailer_bytes = 0
                while True:
                    trailer = self._readline_bounded(
                        MAX_CHUNK_LINE, "Malformed chunk trailer"
                    )
                    if trailer is None:
                        return None
                    trailer_bytes += len(trailer)
                    if trailer_bytes > MAX_TRAILER_BYTES:
                        self.close_connection = True
                        self.send_error(400, "Chunk trailers too large")
                        return None
                    if trailer in (b"\r\n", b"\n"):
                        return b"".join(chunks)
                    field_line = (
                        trailer[:-2] if trailer.endswith(b"\r\n") else trailer[:-1]
                    )
                    name, separator, _ = field_line.partition(b":")
                    if (
                        not separator
                        or not name
                        or any(byte not in _HTTP_TOKEN_BYTES for byte in name)
                    ):
                        self.close_connection = True
                        self.send_error(400, "Malformed chunk trailer")
                        return None
            if total + chunk_size > POST_BODY_LIMIT:
                self._send_payload_too_large()
                return None
            chunk = self.rfile.read(chunk_size)
            if len(chunk) != chunk_size or self.rfile.read(2) != b"\r\n":
                self.close_connection = True
                self.send_error(400, "Malformed chunked encoding")
                return None
            chunks.append(chunk)
            total += chunk_size

    def _decompress_member(self, data: bytes, wbits: int) -> bytes | None:
        output = bytearray()
        remaining_input = data
        while remaining_input:
            decompressor = zlib.decompressobj(wbits)
            pending = remaining_input
            while pending:
                budget = POST_BODY_LIMIT - len(output)
                part = decompressor.decompress(pending, budget + 1)
                if len(part) > budget:
                    self._send_payload_too_large()
                    return None
                output.extend(part)
                pending = decompressor.unconsumed_tail
            if not decompressor.eof:
                self.close_connection = True
                self.send_error(400, "Invalid compressed request body")
                return None
            budget = POST_BODY_LIMIT - len(output)
            tail = decompressor.flush(budget + 1)
            if len(tail) > budget:
                self._send_payload_too_large()
                return None
            output.extend(tail)
            remaining_input = decompressor.unused_data
            if wbits != 16 + zlib.MAX_WBITS and remaining_input:
                self.close_connection = True
                self.send_error(400, "Trailing compressed request data")
                return None
        return bytes(output)

    def _decompress_body(self, data: bytes) -> bytes | None:
        encoding = self.headers.get("Content-Encoding", "").lower().strip()
        try:
            if encoding in ("", "identity"):
                return data
            if encoding in ("gzip", "x-gzip", "deflate") and not data:
                self.close_connection = True
                self.send_error(400, "Invalid compressed request body")
                return None
            if encoding in ("gzip", "x-gzip"):
                return self._decompress_member(data, 16 + zlib.MAX_WBITS)
            if encoding == "deflate":
                wbits = zlib.MAX_WBITS if data[:1] == b"\x78" else -zlib.MAX_WBITS
                return self._decompress_member(data, wbits)
        except zlib.error:
            self.close_connection = True
            self.send_error(400, "Invalid compressed request body")
            return None
        self.close_connection = True
        self.send_error(415, "Unsupported Content-Encoding")
        return None


class LocalHTTPServer(HTTPServer):
    """HTTP server with reusable daemon connection-handler threads.

    ``socketserver.ThreadingMixIn`` creates one OS thread per accepted
    connection. Thread startup has a recurring 15-25 ms scheduling tail on
    Windows, even for loopback requests. A small prewarmed cache removes that
    cost while retaining unbounded growth for long-lived SSE leases and
    concurrent cancellation requests.
    """

    allow_reuse_address = True
    # TCPServer defaults to a backlog of only five connections on Python 3.11.
    # A short loopback burst can fill it while Windows schedules handlers,
    # producing a second latency mode around one scheduler quantum.
    request_queue_size = socket.SOMAXCONN

    def __init__(
        self,
        token: str,
        application: Callable[[str, str, str, bytes | None], HTTPResponse],
    ) -> None:
        self._request_queue: queue.Queue[
            tuple[ServerRequest, tuple[str, int]] | None
        ] = queue.Queue()
        self._worker_condition = threading.Condition()
        self._worker_count = 0
        self._idle_worker_count = 0
        self._closing_workers = False
        self._active_connections: set[socket.socket] = set()
        super().__init__((HOST, 0), RequestHandler)
        self.port = int(self.server_address[1])
        self.token = token
        self.application = application
        self.allowed_hosts = frozenset(
            {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        )
        with self._worker_condition:
            for _ in range(PREWARM_HANDLER_THREADS):
                self._start_worker_locked()
            deadline = time.monotonic() + 1.0
            while (
                self._idle_worker_count < PREWARM_HANDLER_THREADS
                and time.monotonic() < deadline
            ):
                self._worker_condition.wait(deadline - time.monotonic())

    def _start_worker_locked(self) -> None:
        self._worker_count += 1
        worker = threading.Thread(
            target=self._connection_worker,
            name=f"ida-nexus-http-{self._worker_count}",
            daemon=True,
        )
        worker.start()

    def _connection_worker(self) -> None:
        while True:
            with self._worker_condition:
                if self._closing_workers:
                    self._worker_count -= 1
                    self._worker_condition.notify_all()
                    return
                if (
                    self._idle_worker_count >= MAX_IDLE_HANDLER_THREADS
                    and self._worker_count > PREWARM_HANDLER_THREADS
                ):
                    self._worker_count -= 1
                    self._worker_condition.notify_all()
                    return
                self._idle_worker_count += 1
                self._worker_condition.notify_all()
            request = self._request_queue.get()
            with self._worker_condition:
                self._idle_worker_count -= 1
            if request is None:
                with self._worker_condition:
                    self._worker_count -= 1
                    self._worker_condition.notify_all()
                return
            connection, client_address = request
            if not isinstance(connection, socket.socket):
                self.shutdown_request(connection)
                continue
            with self._worker_condition:
                if self._closing_workers:
                    self.shutdown_request(connection)
                    continue
                self._active_connections.add(connection)
            try:
                self.finish_request(connection, client_address)
            except Exception:  # noqa: BLE001 -- socketserver isolation boundary
                self.handle_error(connection, client_address)
            finally:
                with self._worker_condition:
                    self._active_connections.discard(connection)
                    self._worker_condition.notify_all()
                self.shutdown_request(connection)

    def process_request(
        self,
        request: ServerRequest,
        client_address: tuple[str, int],
    ) -> None:
        with self._worker_condition:
            if self._closing_workers:
                self.shutdown_request(request)
                return
            self._request_queue.put((request, client_address))
            if self._idle_worker_count == 0:
                self._start_worker_locked()

    def server_close(self) -> None:
        super().server_close()
        with self._worker_condition:
            if self._closing_workers:
                return
            self._closing_workers = True
            worker_count = self._worker_count
            active_connections = tuple(self._active_connections)
            while True:
                try:
                    pending = self._request_queue.get_nowait()
                except queue.Empty:
                    break
                if pending is not None:
                    self.shutdown_request(pending[0])
            for _ in range(worker_count):
                self._request_queue.put(None)

        for connection in active_connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        with self._worker_condition:
            deadline = time.monotonic() + 1.0
            while self._worker_count > 0 and time.monotonic() < deadline:
                self._worker_condition.wait(deadline - time.monotonic())
