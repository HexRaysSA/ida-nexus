import http.client
import json
import math
import socket
import threading
import time
import uuid
from collections.abc import Callable
from types import TracebackType
from typing import Any, Self

from ._registry import HOST, DatabaseInstance, _event_origin_id
from ._resolver import resolve_instance
from .errors import (
    DatabaseDisconnectedError,
    NexusConnectionError,
    RemoteError,
)
from .instances import wait_database_released
from .models import (
    AnalysisResult,
    DatabaseChangeEvent,
    PythonExecutionResult,
    SaveResult,
    ShutdownResult,
)
from .options import MAX_KEEPALIVE_SECONDS, DatabaseOpenOptions

# Closing an IDB may include a final save. Allow the same five-minute budget as
# explicit saving plus a small margin for worker and registry teardown.
DATABASE_CLOSE_TIMEOUT_SECONDS = 305.0

# The server reaps an idle HTTP/1.1 connection after 30 seconds. Reconnect
# proactively with headroom rather than discovering the close during a POST,
# which cannot safely be retried after its execution status becomes ambiguous.
RPC_CONNECTION_MAX_IDLE_SECONDS = 20.0


class DatabaseChangeSubscription:
    """A closeable iterator over one handle's IDB change notifications."""

    def __init__(self, handle: "DatabaseHandle") -> None:
        self._handle = handle
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._connection: http.client.HTTPConnection | None = None
        self._response: http.client.HTTPResponse | None = None
        self._socket: socket.socket | None = None
        with handle._lock:
            if handle._closed.is_set():
                raise NexusConnectionError("database handle is closed")
            if handle._disconnected.is_set():
                raise DatabaseDisconnectedError(
                    handle._disconnect_reason or "database instance disconnected"
                )
            entry = handle._instance
        self._open(entry)
        with handle._lock:
            if handle._closed.is_set() or handle._disconnected.is_set():
                if handle._disconnected.is_set():
                    error: NexusConnectionError = DatabaseDisconnectedError(
                        handle._disconnect_reason or "database instance disconnected"
                    )
                else:
                    error = NexusConnectionError("database handle is closed")
            else:
                handle._idb_subscriptions.add(self)
                return
        self._close(detach=False)
        raise error

    def _open(self, entry: DatabaseInstance) -> None:
        connection = http.client.HTTPConnection(HOST, entry.port, timeout=10.0)
        try:
            connection.request(
                "GET",
                "/idb_events",
                headers={
                    "Accept": "text/event-stream",
                    "Authorization": f"Bearer {entry._token}",
                },
            )
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise NexusConnectionError(
                f"failed to subscribe to database changes: {exc}"
            ) from exc
        if response.status != 200:
            body = response.read(4096).decode("utf-8", errors="replace")
            connection.close()
            raise NexusConnectionError(
                "failed to subscribe to database changes: "
                f"HTTP {response.status}: {body}"
            )
        stream_socket = connection.sock
        if stream_socket is None and response.fp is not None:
            raw = getattr(response.fp, "raw", None)
            stream_socket = getattr(raw, "_sock", None)
        if stream_socket is None:
            response.close()
            connection.close()
            raise NexusConnectionError(
                "failed to subscribe to database changes: socket unavailable"
            )
        stream_socket.settimeout(None)
        self._connection = connection
        self._response = response
        self._socket = stream_socket

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> DatabaseChangeEvent:
        event_name: bytes | None = None
        event_data: list[bytes] = []
        while True:
            with self._lock:
                if self._closed.is_set() or self._response is None:
                    raise StopIteration
                response = self._response
            try:
                line = response.readline()
            except (
                AttributeError,
                OSError,
                ValueError,
                http.client.HTTPException,
            ) as exc:
                if self._handle._closed.is_set():
                    raise StopIteration from None
                if self._handle._disconnected.is_set():
                    raise DatabaseDisconnectedError(
                        self._handle.disconnect_reason
                        or "database instance disconnected"
                    ) from exc
                if self._closed.is_set():
                    raise StopIteration from None
                self.close()
                raise NexusConnectionError(
                    f"database change stream failed: {exc}"
                ) from exc
            if not line:
                if self._handle._closed.is_set():
                    raise StopIteration
                if self._handle._disconnected.is_set():
                    raise DatabaseDisconnectedError(
                        self._handle.disconnect_reason
                        or "database instance disconnected"
                    )
                if self._closed.is_set():
                    raise StopIteration
                self.close()
                raise NexusConnectionError("database change stream closed")

            line = line.rstrip(b"\r\n")
            if not line:
                if event_name != b"idb_changed":
                    event_name = None
                    event_data = []
                    continue
                try:
                    payload = json.loads(b"\n".join(event_data))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self.close()
                    raise NexusConnectionError(
                        "database change event was not valid JSON"
                    ) from exc
                if not isinstance(payload, dict):
                    self.close()
                    raise NexusConnectionError(
                        "database change event was not an object"
                    )
                return payload
            if line.startswith(b":"):
                continue
            if line.startswith(b"event:"):
                event_name = line[len(b"event:") :].lstrip()
            elif line.startswith(b"data:"):
                event_data.append(line[len(b"data:") :].lstrip())

    def _close(self, *, detach: bool) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        with self._lock:
            response = self._response
            connection = self._connection
            stream_socket = self._socket
            self._response = None
            self._connection = None
            self._socket = None
        if stream_socket is not None:
            try:
                stream_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        raw_stream = None
        if response is not None and response.fp is not None:
            raw_stream = getattr(response.fp, "raw", None)
        if raw_stream is not None:
            try:
                raw_stream.close()
            except OSError:
                pass
        if response is not None:
            try:
                response.close()
            except (OSError, ValueError):
                pass
        if connection is not None:
            connection.close()
        if detach:
            self._handle._forget_idb_subscription(self)

    def close(self) -> None:
        """Close this subscription without closing its database handle."""
        self._close(detach=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class DatabaseHandle:
    """A shared Nexus instance plus one lifetime SSE client lease."""

    def __init__(
        self,
        path: str,
        instance: DatabaseInstance,
        *,
        keepalive: float = 0.0,
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> None:
        if not math.isfinite(keepalive) or not 0 <= keepalive <= MAX_KEEPALIVE_SECONDS:
            raise ValueError(
                f"keepalive must be between 0 and {MAX_KEEPALIVE_SECONDS:g} seconds"
            )
        self.path = path
        self.keepalive = float(keepalive)
        self._lease_id = uuid.uuid4().hex
        self._event_origin_id = _event_origin_id(self._lease_id)
        self._on_disconnect = on_disconnect
        self._lock = threading.Lock()
        self._request_lock = threading.Lock()
        self._closed = threading.Event()
        self._disconnected = threading.Event()
        self._disconnect_reason: str | None = None
        self._instance = instance
        self._rpc_connection: http.client.HTTPConnection | None = None
        self._rpc_last_used: float | None = None
        self._active_operation_id: str | None = None
        self._lease_connection: http.client.HTTPConnection | None = None
        self._lease_response: http.client.HTTPResponse | None = None
        self._lease_socket: socket.socket | None = None
        self._lease_thread: threading.Thread | None = None
        self._idb_subscriptions: set[DatabaseChangeSubscription] = set()
        self._install_lease(instance)
        thread = threading.Thread(
            target=self._monitor_lease,
            name=f"ida-nexus-lease-{instance.pid}",
            daemon=True,
        )
        self._lease_thread = thread
        thread.start()

    @classmethod
    def attach(
        cls,
        instance: DatabaseInstance,
        *,
        path: str | None = None,
        keepalive: float = 0.0,
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> Self:
        """Attach directly to one discovered instance without re-resolving it."""

        requested_path = path or instance.exe_path or instance.idb_path
        if not requested_path:
            raise ValueError("instance has no attachable database path")
        return cls(
            requested_path,
            instance,
            keepalive=keepalive,
            on_disconnect=on_disconnect,
        )

    @classmethod
    def open(
        cls,
        path: str,
        *,
        options: DatabaseOpenOptions | None = None,
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> Self:
        """Attach to a shared instance, spawning a configured worker if needed."""

        options = options or DatabaseOpenOptions()

        def resolve() -> DatabaseInstance:
            return resolve_instance(
                path,
                spawn=options.spawn,
                timeout=options.startup_timeout,
                output_database=options.output_database,
                auto_analysis=options.auto_analysis,
                image_base=options.image_base,
                new_database=options.new_database,
                compiler=options.compiler,
                first_pass_directives=options.first_pass_directives,
                second_pass_directives=options.second_pass_directives,
                disable_fpp=options.disable_fpp,
                entry_point=options.entry_point,
                jit_debugger=options.jit_debugger,
                log_file=options.log_file,
                disable_mouse=options.disable_mouse,
                plugin_options=options.plugin_options,
                processor=options.processor,
                db_compression=options.db_compression,
                run_debugger=options.run_debugger,
                load_resources=options.load_resources,
                script_file=options.script_file,
                script_args=options.script_args,
                file_type=options.file_type,
                file_member=options.file_member,
                empty_database=options.empty_database,
                windows_dir=options.windows_dir,
                no_segmentation=options.no_segmentation,
                debug_flags=options.debug_flags,
            )

        instance = resolve()
        try:
            return cls.attach(
                instance,
                path=path,
                keepalive=options.keepalive,
                on_disconnect=on_disconnect,
            )
        except NexusConnectionError:
            # The worker may cross its zero-lease shutdown boundary between
            # resolve and the SSE handshake. Resolve once more as promised by
            # the instance lifecycle contract.
            time.sleep(0.05)
            replacement = resolve()
            return cls.attach(
                replacement,
                path=path,
                keepalive=options.keepalive,
                on_disconnect=on_disconnect,
            )

    @property
    def instance(self) -> DatabaseInstance:
        """The exact Nexus instance leased by this handle."""
        with self._lock:
            return self._instance

    @property
    def connected(self) -> bool:
        return not self._closed.is_set() and not self._disconnected.is_set()

    @property
    def disconnect_reason(self) -> str | None:
        return self._disconnect_reason

    @property
    def event_origin_id(self) -> str:
        """Opaque identity attached to events produced through this handle."""
        return self._event_origin_id

    def owns_event(self, event: DatabaseChangeEvent) -> bool:
        """Return whether an IDB event was produced through this handle."""
        return event.get("origin_id") == self._event_origin_id

    def set_disconnect_callback(
        self,
        callback: Callable[["DatabaseHandle", str], None],
    ) -> None:
        self._on_disconnect = callback
        if self._disconnected.is_set():
            callback(self, self._disconnect_reason or "database connection closed")

    def subscribe_idb_events(self) -> DatabaseChangeSubscription:
        """Open a closeable iterator of structured IDB events.

        Each event includes its revision and execution attribution. The stream
        can be opened while autoanalysis is running; the server sends its first
        event only after initial autoanalysis has finished. A subscriber that
        cannot keep up with the bounded server queue is disconnected rather
        than receiving an incomplete event history.
        """
        return DatabaseChangeSubscription(self)

    def _forget_idb_subscription(
        self, subscription: DatabaseChangeSubscription
    ) -> None:
        with self._lock:
            self._idb_subscriptions.discard(subscription)

    def _open_lease(
        self, entry: DatabaseInstance
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse, socket.socket]:
        connection = http.client.HTTPConnection(HOST, entry.port, timeout=10.0)
        try:
            connection.request(
                "GET",
                f"/health?sse=1&lease_id={self._lease_id}&keepalive={self.keepalive:g}",
                headers={
                    "Accept": "text/event-stream",
                    "Authorization": f"Bearer {entry._token}",
                },
            )
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise NexusConnectionError(
                f"failed to establish instance lease: {exc}"
            ) from exc
        if response.status != 200:
            body = response.read(4096).decode("utf-8", errors="replace")
            connection.close()
            raise NexusConnectionError(
                f"failed to establish instance lease: HTTP {response.status}: {body}"
            )
        # The 10-second timeout bounds only the handshake. A lease is an
        # indefinite SSE stream; leaving that timeout on the socket can falsely
        # disconnect healthy instances if a heartbeat is delayed by scheduling
        # or system sleep.
        lease_socket = connection.sock
        if lease_socket is None and response.fp is not None:
            raw = getattr(response.fp, "raw", None)
            lease_socket = getattr(raw, "_sock", None)
        if lease_socket is None:
            response.close()
            connection.close()
            raise NexusConnectionError(
                "failed to establish instance lease: socket unavailable"
            )
        lease_socket.settimeout(None)
        return connection, response, lease_socket

    def _install_lease(self, entry: DatabaseInstance) -> None:
        connection, response, lease_socket = self._open_lease(entry)
        with self._lock:
            if self._closed.is_set():
                response.close()
                connection.close()
                raise NexusConnectionError("database handle is closed")
            old_response = self._lease_response
            old_connection = self._lease_connection
            old_socket = self._lease_socket
            self._instance = entry
            self._lease_connection = connection
            self._lease_response = response
            self._lease_socket = lease_socket
        if old_socket is not None:
            try:
                old_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if old_response is not None:
            old_response.close()
        if old_connection is not None:
            old_connection.close()

    def _monitor_lease(self) -> None:
        with self._lock:
            response = self._lease_response
        reason = "database connection closed"
        try:
            if response is not None:
                while not self._closed.is_set() and response.readline():
                    pass
        except (OSError, ValueError, http.client.HTTPException) as exc:
            reason = f"database connection failed: {exc}"
        if self._closed.is_set():
            return
        self._mark_disconnected(reason)

    def _mark_disconnected(self, reason: str) -> None:
        if self._closed.is_set() or self._disconnected.is_set():
            return
        self._disconnect_reason = reason
        self._disconnected.set()
        with self._lock:
            response = self._lease_response
            connection = self._lease_connection
            rpc_connection = self._rpc_connection
            subscriptions = tuple(self._idb_subscriptions)
            self._idb_subscriptions.clear()
            self._lease_response = None
            self._lease_connection = None
            self._lease_socket = None
            self._rpc_connection = None
            self._rpc_last_used = None
        for subscription in subscriptions:
            subscription._close(detach=False)
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        if rpc_connection is not None:
            rpc_connection.close()
        if self._on_disconnect is not None:
            self._on_disconnect(self, reason)

    def _rpc_connection_for(
        self,
        entry: DatabaseInstance,
        timeout: float | None,
    ) -> http.client.HTTPConnection:
        now = time.monotonic()
        stale: http.client.HTTPConnection | None = None
        with self._lock:
            if self._closed.is_set():
                raise NexusConnectionError("database handle is closed")
            connection = self._rpc_connection
            if connection is not None and (
                connection.port != entry.port
                or (
                    self._rpc_last_used is not None
                    and now - self._rpc_last_used >= RPC_CONNECTION_MAX_IDLE_SECONDS
                )
            ):
                stale = connection
                connection = None
                self._rpc_connection = None
                self._rpc_last_used = None
            if connection is None:
                connection = http.client.HTTPConnection(
                    HOST,
                    entry.port,
                    timeout=timeout,
                )
                self._rpc_connection = connection
            connection.timeout = timeout
            sock = connection.sock
        if stale is not None:
            stale.close()
        if sock is not None:
            sock.settimeout(timeout)
        return connection

    def _discard_rpc_connection(
        self,
        connection: http.client.HTTPConnection,
    ) -> None:
        with self._lock:
            if self._rpc_connection is connection:
                self._rpc_connection = None
                self._rpc_last_used = None
        connection.close()

    def _request(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        method: str = "POST",
        timeout: float | None = None,
        unwrap_result: bool = True,
        operation_id: str | None = None,
    ) -> Any:
        request_payload = {**payload, "lease_id": self._lease_id}
        if operation_id is not None:
            request_payload["operation_id"] = operation_id
        body = json.dumps(request_payload).encode("utf-8") if method == "POST" else None
        with self._request_lock:
            if self._closed.is_set():
                raise NexusConnectionError("database handle is closed")
            if self._disconnected.is_set():
                raise DatabaseDisconnectedError(
                    self._disconnect_reason or "database instance disconnected"
                )
            entry = self.instance
            connection = self._rpc_connection_for(entry, timeout)
            if operation_id is not None:
                with self._lock:
                    self._active_operation_id = operation_id
            try:
                connection.request(
                    method,
                    endpoint,
                    body=body,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {entry._token}",
                    },
                )
                response = connection.getresponse()
                try:
                    status = response.status
                    response_body = response.read()
                finally:
                    response.close()
            except (TimeoutError, OSError, http.client.HTTPException) as exc:
                # Do not retry automatically: a POST may have executed before
                # the connection failed. The next operation gets a fresh socket.
                self._discard_rpc_connection(connection)
                raise NexusConnectionError(f"Nexus request failed: {exc}") from exc
            finally:
                if operation_id is not None:
                    with self._lock:
                        if self._active_operation_id == operation_id:
                            self._active_operation_id = None
            with self._lock:
                if self._rpc_connection is connection:
                    self._rpc_last_used = time.monotonic()

        try:
            response_payload = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if status != 200:
                raise NexusConnectionError(
                    f"Nexus request failed with HTTP {status}"
                ) from exc
            raise NexusConnectionError("Nexus response was not valid JSON") from exc
        if not isinstance(response_payload, dict):
            raise NexusConnectionError("Nexus response was not a JSON object")
        if status != 200 or (unwrap_result and not response_payload.get("ok")):
            error = response_payload.get("error")
            if isinstance(error, dict):
                details = {
                    str(key): value
                    for key, value in error.items()
                    if key not in {"code", "message"}
                }
                raise RemoteError(
                    str(error.get("code", "remote_error")),
                    str(error.get("message", "Nexus request failed")),
                    status,
                    details,
                )
            raise NexusConnectionError(f"Nexus request failed with HTTP {status}")
        return response_payload.get("result") if unwrap_result else response_payload

    def execute_python(
        self,
        code: str,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> PythonExecutionResult:
        """Execute Python with optional display attribution.

        Stateless execution resets this handle's namespace. ``operation_label``
        is opaque, untrusted display text propagated to IDB change events.
        """

        payload: dict[str, Any] = {
            "code": code,
            "persist_globals": persist_globals,
        }
        if operation_label is not None:
            payload["operation_label"] = operation_label
        if filename is not None:
            payload["filename"] = filename
        if timeout is not None:
            payload["timeout"] = timeout
        # Leave enough HTTP time for the server to return its structured
        # operation-timeout response.
        http_timeout = None if timeout is None else timeout + 5.0
        return self._request(
            "/execute_python",
            payload,
            timeout=http_timeout,
            operation_id=operation_id or uuid.uuid4().hex,
        )

    def poll_autoanalysis(self) -> AnalysisResult:
        """Return status without itself enabling or advancing autoanalysis.

        A GUI whose persistent analysis setting is off reports ``disabled`` and
        a settled barrier; workers may already be advancing analysis in the
        background after publication.
        """
        result = self._request(
            "/poll_autoanalysis",
            {},
            method="GET",
            timeout=5.0,
            unwrap_result=False,
        )
        if not isinstance(result, dict) or not isinstance(result.get("complete"), bool):
            raise NexusConnectionError("poll_autoanalysis returned an invalid result")
        return result

    def wait_autoanalysis(
        self,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
    ) -> AnalysisResult:
        """Wait for initial autoanalysis through the public Nexus route.

        This also explicitly analyzes a GUI barrier previously settled as
        ``disabled``, while restoring the prior temporary runtime state afterward.
        """
        payload: dict[str, Any] = {}
        if timeout is not None:
            payload["timeout"] = timeout
        http_timeout = None if timeout is None else timeout + 5.0
        result = self._request(
            "/wait_autoanalysis",
            payload,
            timeout=http_timeout,
            unwrap_result=False,
            operation_id=operation_id or uuid.uuid4().hex,
        )
        if not isinstance(result, dict) or not isinstance(result.get("complete"), bool):
            raise NexusConnectionError("wait_autoanalysis returned an invalid result")
        return result

    def cancel_operation(self, operation_id: str) -> bool:
        """Cancel one identified in-flight operation over a control connection."""
        with self._lock:
            if self._active_operation_id != operation_id:
                return False
            entry = self._instance

        connection = http.client.HTTPConnection(HOST, entry.port, timeout=2.0)
        try:
            body = json.dumps(
                {
                    "lease_id": self._lease_id,
                    "operation_id": operation_id,
                }
            ).encode("utf-8")
            connection.request(
                "POST",
                "/cancel_operation",
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {entry._token}",
                },
            )
            response = connection.getresponse()
            try:
                payload = json.loads(response.read())
                return bool(
                    response.status == 200
                    and isinstance(payload, dict)
                    and isinstance(payload.get("result"), dict)
                    and payload["result"].get("cancelled") is True
                )
            finally:
                response.close()
        except (
            TimeoutError,
            OSError,
            http.client.HTTPException,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return False
        finally:
            connection.close()

    def cancel_active(self, timeout: float = 2.0) -> bool:
        """Cancel this handle's in-flight operation over a control connection."""
        deadline = time.monotonic() + timeout
        with self._lock:
            operation_id = self._active_operation_id
        if operation_id is None:
            return False

        while True:
            if self.cancel_operation(operation_id):
                return True
            with self._lock:
                if self._active_operation_id != operation_id:
                    return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def save_database(self) -> SaveResult:
        result = self._request("/save_database", {}, timeout=305.0)
        if not isinstance(result, dict):
            raise NexusConnectionError("save_database returned an invalid result")
        return result

    def shutdown_database(self, *, save: bool = True) -> ShutdownResult:
        """Shut down an exclusively leased managed worker, saving or discarding it."""
        if not isinstance(save, bool):
            raise TypeError("save must be a boolean")
        result = self._request("/shutdown_database", {"save": save}, timeout=5.0)
        if (
            not isinstance(result, dict)
            or result.get("shutting_down") is not True
            or result.get("save") is not save
        ):
            raise NexusConnectionError("shutdown_database returned an invalid result")
        return result

    def _release_remote_lease(self) -> bool:
        """Best-effort release; return whether it committed final IDB shutdown."""

        entry = self.instance
        connection = http.client.HTTPConnection(HOST, entry.port, timeout=2.0)
        try:
            body = json.dumps({"lease_id": self._lease_id}).encode("utf-8")
            connection.request(
                "POST",
                "/release_lease",
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {entry._token}",
                },
            )
            response = connection.getresponse()
            try:
                payload = json.loads(response.read())
                result = payload.get("result") if isinstance(payload, dict) else None
                return bool(
                    isinstance(result, dict) and result.get("shutdown_pending") is True
                )
            finally:
                response.close()
        except (
            TimeoutError,
            OSError,
            http.client.HTTPException,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            # Closing the SSE socket below remains the authoritative fallback.
            return False
        finally:
            connection.close()

    def close(
        self,
        *,
        wait_for_database: bool = False,
        timeout: float = DATABASE_CLOSE_TIMEOUT_SECONDS,
    ) -> None:
        """Release this lease and optionally wait for a final managed IDB close."""

        if not isinstance(wait_for_database, bool):
            raise TypeError("wait_for_database must be a boolean")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("timeout must be a finite non-negative number")
        if self._closed.is_set():
            return
        self._closed.set()
        with self._lock:
            subscriptions = tuple(self._idb_subscriptions)
            self._idb_subscriptions.clear()
        for subscription in subscriptions:
            subscription._close(detach=False)
        shutdown_pending = self._release_remote_lease()
        with self._lock:
            response = self._lease_response
            connection = self._lease_connection
            lease_socket = self._lease_socket
            rpc_connection = self._rpc_connection
            thread = self._lease_thread
            self._lease_response = None
            self._lease_connection = None
            self._lease_socket = None
            self._rpc_connection = None
            self._rpc_last_used = None
        if lease_socket is not None:
            try:
                lease_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        # On Windows, shutdown() does not wake a BufferedReader blocked in
        # readline() when HTTPResponse owns the socket through SocketIO. Close
        # that raw stream directly; HTTPResponse.close() would instead wait for
        # the BufferedReader lock until the next SSE heartbeat.
        raw_stream = None
        if response is not None and response.fp is not None:
            raw_stream = getattr(response.fp, "raw", None)
        if raw_stream is not None:
            try:
                raw_stream.close()
            except OSError:
                pass
        if rpc_connection is not None:
            rpc_connection.close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if response is not None:
            try:
                response.close()
            except (OSError, ValueError):
                # The raw stream was intentionally closed above to wake the
                # monitor; HTTPResponse.flush() may observe that closed stream.
                pass
        if connection is not None:
            connection.close()

        if (
            wait_for_database
            and shutdown_pending
            and not wait_database_released(
                self.instance,
                timeout=float(timeout),
            )
        ):
            raise NexusConnectionError(
                f"timed out after {float(timeout):g}s waiting for the IDB to close"
            )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
