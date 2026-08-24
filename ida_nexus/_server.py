import json
import logging
import math
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from io import BufferedIOBase
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs

from ._http import HOST, HTTPResponse, LocalHTTPServer, json_response
from ._registry import DatabaseInstance, InstanceIdentity, InstanceRegistration
from ._runtime import USER_CODE_FILENAME, AnalysisState, APIError

logger = logging.getLogger(__name__)
DEFAULT_LEASE_GRACE_SECONDS = 20.0
DEFAULT_SSE_HEARTBEAT_SECONDS = 5.0
MAX_KEEPALIVE_SECONDS = 3600.0
_AUTOANALYSIS_SCHEDULER_YIELD_SECONDS = 0.001


@dataclass
class _Lease:
    keepalive: float
    stop: threading.Event


class NexusBackend(Protocol):
    def execute_python(
        self,
        code: str,
        timeout: float | None,
        *,
        lease_id: str | None = None,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> Any: ...

    def cancel_active(self) -> None: ...

    def release_session(self, lease_id: str) -> None: ...

    def advance_autoanalysis(self) -> dict[str, Any]: ...

    def wait_autoanalysis(self, timeout: float | None) -> dict[str, Any]: ...

    def save_database(self) -> dict[str, Any]: ...

    def enable_idb_change_hook(self) -> None: ...

    def disable_idb_change_hook(self) -> None: ...

    def subscribe_idb_changes(self) -> Any: ...

    def wait_idb_change(
        self, subscriber: Any, timeout: float
    ) -> dict[str, Any] | None: ...


class NexusHTTPServer:
    """Authenticated local Nexus API, registration, and client leases."""

    def __init__(
        self,
        backend: NexusBackend,
        identity: InstanceIdentity,
        analysis_state: AnalysisState,
        registry_dir: str | os.PathLike[str],
        *,
        token: str | None = None,
        record_suffix: str | None = None,
        lease_grace: float = DEFAULT_LEASE_GRACE_SECONDS,
        heartbeat_interval: float = DEFAULT_SSE_HEARTBEAT_SECONDS,
        on_shutdown: Callable[[], None] | None = None,
    ) -> None:
        self.backend = backend
        self.identity = identity
        self.analysis_state = analysis_state
        self.registry_dir = Path(registry_dir)
        if not math.isfinite(lease_grace) or lease_grace < 0:
            raise ValueError("lease_grace must be a finite non-negative number")
        if not math.isfinite(heartbeat_interval) or heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be a positive finite number")
        self.token = token or str(uuid.uuid4())
        self.record_suffix = record_suffix
        self.lease_grace = lease_grace
        self.heartbeat_interval = heartbeat_interval
        self.on_shutdown = on_shutdown

        self._lock = threading.Lock()
        self._activity = threading.Condition()
        self._httpd: LocalHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._watchdog: threading.Thread | None = None
        self._analysis_thread: threading.Thread | None = None
        self._registration: InstanceRegistration | None = None
        self._entry: DatabaseInstance | None = None
        self._draining = False
        self._shutdown_requested = False
        self._save_on_shutdown = True
        self._active_leases = 0
        self._active_requests = 0
        self._leases: dict[str, _Lease] = {}
        self._shutdown_at: float | None = time.monotonic() + self.lease_grace
        self._backend_lock = threading.Lock()
        # Foreground operations announce their intent before contending for the
        # backend lock. The analysis scheduler then yields deterministically
        # instead of relying on threading.Lock fairness.
        self._foreground_waiters = 0
        self._running_lease_id: str | None = None
        self._running_operation_id: str | None = None
        self._pending_operations: set[tuple[str | None, str]] = set()
        self._cancelled_operations: set[tuple[str | None, str]] = set()
        self._stream_stop = threading.Event()
        self._idb_event_subscribers = 0
        self._idb_event_hook_lock = threading.Lock()
        self._idb_event_hook_enabled = False
        self.analysis_state.add_completion_callback(self._enable_idb_event_hook)

    @property
    def port(self) -> int | None:
        return self._httpd.port if self._httpd is not None else None

    @property
    def url(self) -> str | None:
        return f"http://{HOST}:{self.port}" if self.port is not None else None

    @property
    def entry(self) -> DatabaseInstance | None:
        return self._entry

    @property
    def save_on_shutdown(self) -> bool:
        """Whether the lifecycle owner should persist the database during teardown."""
        with self._activity:
            return self._save_on_shutdown

    def start(self) -> None:
        with self._lock:
            if self._httpd is not None:
                return
            self._draining = False
            self._shutdown_requested = False
            self._save_on_shutdown = True
            self._stream_stop.clear()
            self._shutdown_at = time.monotonic() + self.lease_grace
            registration = InstanceRegistration(
                self.registry_dir,
                self.identity,
                token=self.token,
                record_suffix=self.record_suffix,
            )
            httpd = LocalHTTPServer(self.token, self._dispatch)
            serving = threading.Event()
            thread = threading.Thread(
                target=self._serve,
                args=(httpd, serving),
                name="ida-nexus-http",
                daemon=True,
            )
            self._registration = registration
            self._httpd = httpd
            self._thread = thread

        try:
            thread.start()
            if not serving.wait(timeout=2.0) or not thread.is_alive():
                raise RuntimeError("HTTP server thread did not start")
            self._entry = registration.publish(httpd.port)
            if self.identity.managed:
                watchdog = threading.Thread(
                    target=self._watch_leases,
                    name="ida-nexus-leases",
                    daemon=True,
                )
                self._watchdog = watchdog
                watchdog.start()
        except Exception:
            self.stop()
            raise

    @staticmethod
    def _serve(httpd: LocalHTTPServer, serving: threading.Event) -> None:
        serving.set()
        try:
            httpd.serve_forever(poll_interval=0.1)
        except Exception:
            logger.exception("Nexus HTTP server stopped unexpectedly")

    def start_autoanalysis(self) -> None:
        """Start initial analysis after publication without blocking discovery.

        Bounded slices use the same backend serialization and hook-driven
        completion path as every other operation, but release the operation lock
        between slices. Low-level clients can therefore execute during analysis;
        policy layers such as the MCP may still explicitly wait first.
        """

        with self._lock:
            if self._httpd is None:
                raise RuntimeError("Nexus server must be started before autoanalysis")
            if self.analysis_state.snapshot()["status"] == "complete":
                return
            if self._analysis_thread is not None:
                return
            thread = threading.Thread(
                target=self._run_startup_autoanalysis,
                name="ida-nexus-autoanalysis",
                daemon=True,
            )
            self._analysis_thread = thread
        thread.start()

    def _acquire_startup_analysis(self) -> bool:
        """Acquire the backend only when no foreground operation is queued."""

        while not self._stream_stop.is_set():
            with self._activity:
                if self._draining or self._shutdown_requested:
                    return False
                if self._foreground_waiters == 0 and self._backend_lock.acquire(
                    blocking=False
                ):
                    return True
            if self._stream_stop.wait(_AUTOANALYSIS_SCHEDULER_YIELD_SECONDS):
                return False
        return False

    def _run_startup_autoanalysis(self) -> None:
        try:
            while self._acquire_startup_analysis():
                try:
                    # Shutdown may begin while this thread is waiting for the
                    # backend. Never start a fresh slice after that boundary.
                    with self._activity:
                        if (
                            self._stream_stop.is_set()
                            or self._draining
                            or self._shutdown_requested
                        ):
                            return
                    if self.analysis_state.complete.is_set():
                        return
                    status = self.backend.advance_autoanalysis()
                finally:
                    self._backend_lock.release()
                if status["complete"]:
                    return
                # Let newly arriving request threads register as foreground
                # waiters before considering the next background slice.
                if self._stream_stop.wait(_AUTOANALYSIS_SCHEDULER_YIELD_SECONDS):
                    return
        except APIError as exc:
            logger.warning("Nexus startup autoanalysis stopped: %s", exc)
        except Exception:
            logger.exception("Nexus startup autoanalysis failed")

    def release_registration(self) -> None:
        """Withdraw ownership after the owning IDB has detached or closed."""

        registration = self._registration
        self._registration = None
        self._entry = None
        if registration is not None:
            registration.release()

    def stop(self) -> None:
        # Keep the registry record and lifetime lock together until the owning
        # IDB has detached or closed. While the listener is stopped, discovery
        # classifies this record as BLOCKED instead of spawning over it.
        self._stream_stop.set()
        with self._activity:
            self._draining = True
            for lease in self._leases.values():
                lease.stop.set()
            self._activity.notify_all()
        with self._lock:
            httpd = self._httpd
            thread = self._thread
            watchdog = self._watchdog
            analysis_thread = self._analysis_thread
            self._httpd = None
            self._thread = None
            self._watchdog = None

        if httpd is not None:
            # BaseServer.shutdown() deadlocks if serve_forever() never started.
            if thread is not None and thread.is_alive():
                httpd.shutdown()
                if thread is not threading.current_thread():
                    thread.join(timeout=5.0)
            httpd.server_close()
        if (
            watchdog is not None
            and watchdog.is_alive()
            and watchdog is not threading.current_thread()
        ):
            watchdog.join(timeout=2.0)
        if (
            analysis_thread is not None
            and analysis_thread.is_alive()
            and analysis_thread is not threading.current_thread()
        ):
            # Database teardown must not race a scheduler still using IDA.
            analysis_thread.join()

    def _watch_leases(self) -> None:
        while not self._stream_stop.is_set():
            with self._activity:
                while not self._draining:
                    now = time.monotonic()
                    shutdown_at = self._shutdown_at
                    eligible = (
                        self._active_leases == 0
                        and self._active_requests == 0
                        and shutdown_at is not None
                    )
                    if eligible and shutdown_at is not None:
                        remaining = shutdown_at - now
                        if remaining <= 0:
                            self._draining = True
                            break
                        self._activity.wait(timeout=min(remaining, 1.0))
                    else:
                        self._activity.wait(timeout=1.0)
                    if self._stream_stop.is_set():
                        return
                if not self._draining or self._stream_stop.is_set():
                    return

            # No lease or operation can enter after _draining is set. Keep the
            # ownership record published while the worker saves and closes.
            self.stop()
            if self.on_shutdown is not None:
                try:
                    self.on_shutdown()
                except Exception:
                    logger.exception("Nexus shutdown callback failed")
            return

    def _lease_opened(self, lease_id: str, keepalive: float) -> _Lease | None:
        with self._activity:
            if self._draining or self._shutdown_requested or lease_id in self._leases:
                return None
            lease = _Lease(keepalive=keepalive, stop=threading.Event())
            self._leases[lease_id] = lease
            self._active_leases = len(self._leases)
            self._shutdown_at = None
            self._activity.notify_all()
            return lease

    def _detach_lease(self, lease_id: str) -> tuple[bool, bool]:
        """Detach a lease and report whether final managed shutdown is committed."""

        with self._activity:
            lease = self._leases.pop(lease_id, None)
            if lease is None:
                # Preserve the final-shutdown result if the SSE disconnect
                # raced an idempotent explicit release of the same lease.
                shutdown_pending = bool(
                    self.identity.managed
                    and self._shutdown_requested
                    and self._active_leases == 0
                )
                return False, shutdown_pending
            lease.stop.set()
            self._active_leases = len(self._leases)
            # Treat cancellation and session cleanup like an active request so
            # managed shutdown cannot close the IDB before cleanup completes.
            self._active_requests += 1
            shutdown_pending = False
            if self._active_leases == 0:
                self._shutdown_at = time.monotonic() + lease.keepalive
                if self.identity.managed and lease.keepalive == 0:
                    # Make a zero-keepalive final release deterministic: reject
                    # a racing replacement lease while existing work unwinds.
                    self._shutdown_requested = True
                    shutdown_pending = True
            self._activity.notify_all()
            return True, shutdown_pending

    def _finish_lease_close(self, lease_id: str) -> None:
        try:
            with self._activity:
                owns_running_operation = self._running_lease_id == lease_id
            if owns_running_operation:
                # The backend lock keeps operation handoff blocked until this
                # cancellation reaches the operation owned by the released lease.
                try:
                    self.backend.cancel_active()
                except Exception:
                    logger.exception("Nexus operation cancellation failed")
            try:
                self.backend.release_session(lease_id)
            except Exception:
                logger.exception("Nexus lease session cleanup failed")
        finally:
            self._request_finished()

    def _lease_closed(self, lease_id: str) -> None:
        released, _shutdown_pending = self._detach_lease(lease_id)
        if released:
            self._finish_lease_close(lease_id)

    def _request_started(self, lease_id: str | None) -> None:
        with self._activity:
            if self._draining or self._shutdown_requested:
                raise APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            if lease_id is not None and lease_id not in self._leases:
                raise APIError(
                    "lease_released", "The client lease is no longer active", status=409
                )
            self._active_requests += 1

    def _request_finished(self) -> None:
        with self._activity:
            if self._active_requests > 0:
                self._active_requests -= 1
            self._activity.notify_all()

    def _run_operation(
        self,
        lease_id: str | None,
        operation: Callable[[], Any],
        operation_id: str | None = None,
    ) -> Any:
        operation_key = (lease_id, operation_id) if operation_id is not None else None
        with self._activity:
            if operation_key is not None:
                if operation_key in self._pending_operations:
                    raise APIError(
                        "duplicate_operation",
                        "The operation id is already active",
                        status=409,
                    )
                self._pending_operations.add(operation_key)
            # Publish foreground intent atomically with the operation key so
            # the background scheduler cannot slip into the backend first.
            self._foreground_waiters += 1
        try:
            try:
                if operation_key is None:
                    self._backend_lock.acquire()
                else:
                    while not self._backend_lock.acquire(timeout=0.05):
                        with self._activity:
                            if operation_key in self._cancelled_operations:
                                raise APIError(
                                    "operation_cancelled",
                                    "The operation was cancelled",
                                    status=409,
                                )
            finally:
                with self._activity:
                    self._foreground_waiters -= 1
                    self._activity.notify_all()
            try:
                with self._activity:
                    if lease_id is not None and lease_id not in self._leases:
                        raise APIError(
                            "lease_released",
                            "The client lease is no longer active",
                            status=409,
                        )
                    if (
                        operation_key is not None
                        and operation_key in self._cancelled_operations
                    ):
                        raise APIError(
                            "operation_cancelled",
                            "The operation was cancelled",
                            status=409,
                        )
                    self._running_lease_id = lease_id
                    self._running_operation_id = operation_id
                try:
                    return operation()
                finally:
                    with self._activity:
                        if (
                            self._running_lease_id == lease_id
                            and self._running_operation_id == operation_id
                        ):
                            self._running_lease_id = None
                            self._running_operation_id = None
                        self._activity.notify_all()
            finally:
                self._backend_lock.release()
        finally:
            if operation_key is not None:
                with self._activity:
                    self._pending_operations.discard(operation_key)
                    self._cancelled_operations.discard(operation_key)
                    self._activity.notify_all()

    def _cancel_operation(self, lease_id: str | None, operation_id: str) -> bool:
        if lease_id is None:
            raise APIError("invalid_lease", "lease_id is required")
        operation_key = (lease_id, operation_id)
        with self._activity:
            if operation_key not in self._pending_operations:
                return False
            self._cancelled_operations.add(operation_key)
            if (
                self._running_lease_id == lease_id
                and self._running_operation_id == operation_id
            ):
                # Serialize cancellation with the running-operation fields so a
                # finishing operation cannot hand the backend to a successor
                # before cancel_active() observes the intended generation.
                self.backend.cancel_active()
            return True

    def _request_shutdown(self, lease_id: str | None, save: bool) -> None:
        if lease_id is None:
            raise APIError("invalid_lease", "lease_id is required")
        with self._activity:
            if not self.identity.managed or self.identity.backend != "idalib":
                raise APIError(
                    "shutdown_not_supported",
                    "Only managed idalib workers can be shut down remotely",
                    status=409,
                )
            if set(self._leases) != {lease_id}:
                raise APIError(
                    "instance_shared",
                    "The managed worker has another active lease",
                    status=409,
                )
            if (
                self._active_requests != 1
                or self._running_operation_id is not None
                or self._pending_operations
            ):
                raise APIError(
                    "instance_busy",
                    "The managed worker has another active operation",
                    status=409,
                )
            self._shutdown_requested = True
            self._save_on_shutdown = save

    def _begin_requested_shutdown(self) -> None:
        with self._activity:
            if not self._shutdown_requested or self._draining:
                return
            self._draining = True
            self._activity.notify_all()

    def _health_payload(self) -> dict[str, Any]:
        with self._activity:
            if self._draining or self._shutdown_requested:
                raise APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            entry = self._entry
        if entry is None:
            raise APIError(
                "instance_starting",
                "The instance has not finished registration",
                status=503,
            )
        return {"status": "ok", **entry.health_identity()}

    @staticmethod
    def _lease_parameters(parameters: dict[str, list[str]]) -> tuple[str, float]:
        values = parameters.get("lease_id")
        lease_id = values[0] if values and len(values) == 1 else uuid.uuid4().hex
        if not lease_id or len(lease_id) > 128:
            raise APIError("invalid_lease", "lease_id must be 1 to 128 characters")
        keepalive_values = parameters.get("keepalive")
        raw_keepalive = keepalive_values[0] if keepalive_values else "0"
        try:
            keepalive = float(raw_keepalive)
        except (TypeError, ValueError) as exc:
            raise APIError(
                "invalid_keepalive", "keepalive must be a non-negative number"
            ) from exc
        if (
            not math.isfinite(keepalive)
            or keepalive < 0
            or keepalive > MAX_KEEPALIVE_SECONDS
        ):
            raise APIError(
                "invalid_keepalive",
                f"keepalive must be between 0 and {MAX_KEEPALIVE_SECONDS:g} seconds",
            )
        return lease_id, keepalive

    def _lease_response(self, parameters: dict[str, list[str]]) -> HTTPResponse:
        lease_id, keepalive = self._lease_parameters(parameters)
        lease = self._lease_opened(lease_id, keepalive)
        if lease is None:
            return self._failure(
                APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            )
        try:
            payload = json.dumps(self._health_payload(), separators=(",", ":"))
        except Exception:
            self._lease_closed(lease_id)
            raise

        def stream(file: BufferedIOBase) -> None:
            file.write(f"event: health\ndata: {payload}\n\n".encode())
            file.flush()
            while not lease.stop.wait(self.heartbeat_interval):
                if self._stream_stop.is_set():
                    return
                file.write(b": keepalive\n\n")
                file.flush()

        return HTTPResponse(
            status=200,
            content_type="text/event-stream",
            stream=stream,
            after_send=lambda: self._lease_closed(lease_id),
        )

    def _idb_event_subscribe(self) -> None:
        with self._activity:
            if self._draining or self._shutdown_requested:
                raise APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            self._idb_event_subscribers += 1
        if self.analysis_state.complete.is_set():
            try:
                self._enable_idb_event_hook()
            except Exception:
                self._idb_event_unsubscribe()
                raise

    def _enable_idb_event_hook(self) -> bool:
        """Install the hook once analysis is complete and a subscriber remains."""
        with self._idb_event_hook_lock:
            with self._activity:
                wanted = (
                    self.analysis_state.complete.is_set()
                    and self._idb_event_subscribers > 0
                    and not self._draining
                    and not self._shutdown_requested
                )
            if wanted and not self._idb_event_hook_enabled:
                self.backend.enable_idb_change_hook()
                self._idb_event_hook_enabled = True
            return wanted

    def _idb_event_unsubscribe(self) -> None:
        with self._activity:
            self._idb_event_subscribers -= 1
            idle = self._idb_event_subscribers == 0
        if not idle:
            return
        with self._idb_event_hook_lock:
            with self._activity:
                idle = self._idb_event_subscribers == 0
            if idle and self._idb_event_hook_enabled:
                self.backend.disable_idb_change_hook()
                self._idb_event_hook_enabled = False

    def _idb_events_response(self) -> HTTPResponse:
        subscriber = self.backend.subscribe_idb_changes()
        self._idb_event_subscribe()
        unsubscribed = False

        def unsubscribe_once() -> None:
            nonlocal unsubscribed
            if not unsubscribed:
                unsubscribed = True
                self._idb_event_unsubscribe()

        def stream(file: BufferedIOBase) -> None:
            while not self.analysis_state.complete.wait(self.heartbeat_interval):
                if self._stream_stop.is_set():
                    return
                file.write(b": keepalive\n\n")
                file.flush()
            if self._stream_stop.is_set() or not self._enable_idb_event_hook():
                return
            while not self._stream_stop.is_set():
                try:
                    event = self.backend.wait_idb_change(
                        subscriber, self.heartbeat_interval
                    )
                except OverflowError:
                    return
                if self._stream_stop.is_set():
                    return
                if event is None:
                    file.write(b": keepalive\n\n")
                else:
                    payload = json.dumps(event, separators=(",", ":"))
                    file.write(f"event: idb_changed\ndata: {payload}\n\n".encode())
                file.flush()

        return HTTPResponse(
            status=200,
            content_type="text/event-stream",
            stream=stream,
            after_send=unsubscribe_once,
        )

    @staticmethod
    def _decode_object(body: bytes | None) -> dict[str, Any]:
        if not body:
            return {}
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise APIError("invalid_json", "Request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise APIError("invalid_request", "Request body must be a JSON object")
        return payload

    @staticmethod
    def _payload_lease_id(payload: dict[str, Any]) -> str | None:
        lease_id = payload.get("lease_id")
        if lease_id is None:
            return None
        if not isinstance(lease_id, str) or not lease_id or len(lease_id) > 128:
            raise APIError("invalid_lease", "lease_id must be 1 to 128 characters")
        return lease_id

    @staticmethod
    def _operation_id(payload: dict[str, Any]) -> str | None:
        operation_id = payload.get("operation_id")
        if operation_id is None:
            return None
        if (
            not isinstance(operation_id, str)
            or not operation_id
            or len(operation_id) > 128
        ):
            raise APIError(
                "invalid_operation",
                "operation_id must be 1 to 128 characters",
            )
        return operation_id

    @staticmethod
    def _operation_label(payload: dict[str, Any]) -> str | None:
        operation_label = payload.get("operation_label")
        if operation_label is None:
            return None
        if (
            not isinstance(operation_label, str)
            or not operation_label.strip()
            or len(operation_label) > 1024
        ):
            raise APIError(
                "invalid_operation_label",
                "operation_label must be 1 to 1024 non-whitespace characters",
            )
        return operation_label

    @staticmethod
    def _persist_globals(payload: dict[str, Any]) -> bool:
        persist_globals = payload.get("persist_globals", False)
        if not isinstance(persist_globals, bool):
            raise APIError(
                "invalid_persist_globals",
                "persist_globals must be a boolean",
            )
        return persist_globals

    @staticmethod
    def _filename(payload: dict[str, Any]) -> str:
        filename = payload.get("filename", USER_CODE_FILENAME)
        if not isinstance(filename, str) or not filename.strip():
            raise APIError("invalid_filename", "filename must be a non-empty string")
        return filename

    @staticmethod
    def _timeout(payload: dict[str, Any]) -> float | None:
        timeout = payload.get("timeout")
        if timeout is None:
            return None
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise APIError("invalid_timeout", "timeout must be a positive number")
        timeout = float(timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise APIError(
                "invalid_timeout", "timeout must be a positive finite number"
            )
        return timeout

    @staticmethod
    def _success(
        result: Any,
        *,
        after_send: Callable[[], None] | None = None,
    ) -> HTTPResponse:
        try:
            return json_response(
                200,
                {"ok": True, "result": result},
                after_send=after_send,
            )
        except (TypeError, ValueError) as exc:
            raise APIError(
                "invalid_result",
                f"Nexus results must be valid JSON: {exc}",
                status=500,
            ) from exc

    @staticmethod
    def _failure(error: APIError) -> HTTPResponse:
        payload: dict[str, Any] = {
            "ok": False,
            "error": {
                "code": error.code,
                "message": str(error),
            },
        }
        payload["error"].update(error.details)
        return json_response(error.status, payload)

    def _dispatch(
        self,
        method: str,
        path: str,
        query: str,
        body: bytes | None,
    ) -> HTTPResponse:
        try:
            if method == "GET" and path == "/health":
                parameters = parse_qs(query, keep_blank_values=True)
                if parameters.get("sse") == ["1"]:
                    return self._lease_response(parameters)
                return json_response(200, self._health_payload())

            if method == "GET" and path == "/idb_events":
                return self._idb_events_response()

            if method == "POST" and path == "/release_lease":
                payload = self._decode_object(body)
                lease_id = self._payload_lease_id(payload)
                if lease_id is None:
                    raise APIError("invalid_lease", "lease_id is required")
                release_id: str = lease_id
                released, shutdown_pending = self._detach_lease(release_id)

                def finish_release() -> None:
                    if released:
                        self._finish_lease_close(release_id)

                return json_response(
                    200,
                    {
                        "ok": True,
                        "result": {
                            "released": True,
                            "shutdown_pending": shutdown_pending,
                        },
                    },
                    after_send=finish_release,
                )

            payload = (
                self._decode_object(body)
                if method == "POST"
                and path
                in {
                    "/wait_autoanalysis",
                    "/execute_python",
                    "/cancel_operation",
                    "/save_database",
                    "/shutdown_database",
                }
                else {}
            )
            lease_id = self._payload_lease_id(payload)
            self._request_started(lease_id)
            try:
                if method == "GET" and path == "/poll_autoanalysis":
                    return json_response(200, self.analysis_state.snapshot())
                if method == "GET" and path == "/wait_autoanalysis":
                    return json_response(
                        200,
                        self._run_operation(
                            None, lambda: self.backend.wait_autoanalysis(None)
                        ),
                    )
                if method == "POST" and path == "/wait_autoanalysis":
                    return json_response(
                        200,
                        self._run_operation(
                            lease_id,
                            lambda: self.backend.wait_autoanalysis(
                                self._timeout(payload)
                            ),
                            self._operation_id(payload),
                        ),
                    )
                if method == "POST" and path == "/execute_python":
                    code = payload.get("code")
                    if not isinstance(code, str) or not code.strip():
                        raise APIError(
                            "invalid_code", "code must be a non-empty string"
                        )
                    persist_globals = self._persist_globals(payload)
                    if persist_globals and lease_id is None:
                        raise APIError(
                            "invalid_lease",
                            "persist_globals requires an active lease",
                        )
                    filename = self._filename(payload)
                    operation_id = self._operation_id(payload)
                    operation_label = self._operation_label(payload)
                    return self._success(
                        self._run_operation(
                            lease_id,
                            lambda: self.backend.execute_python(
                                code,
                                self._timeout(payload),
                                lease_id=lease_id,
                                operation_id=operation_id,
                                operation_label=operation_label,
                                persist_globals=persist_globals,
                                filename=filename,
                            ),
                            operation_id,
                        )
                    )
                if method == "POST" and path == "/cancel_operation":
                    operation_id = self._operation_id(payload)
                    if operation_id is None:
                        raise APIError(
                            "invalid_operation",
                            "operation_id is required",
                        )
                    return self._success(
                        {
                            "cancelled": self._cancel_operation(
                                lease_id,
                                operation_id,
                            )
                        }
                    )
                if method == "POST" and path == "/save_database":
                    return self._success(
                        self._run_operation(lease_id, self.backend.save_database)
                    )
                if method == "POST" and path == "/shutdown_database":
                    save = payload.get("save")
                    if not isinstance(save, bool):
                        raise APIError("invalid_save", "save must be a boolean")
                    self._request_shutdown(lease_id, save)
                    return self._success(
                        {"shutting_down": True, "save": save},
                        after_send=self._begin_requested_shutdown,
                    )
                return json_response(404, {"ok": False, "error": "Not Found"})
            finally:
                self._request_finished()
        except APIError as exc:
            return self._failure(exc)
        except Exception as exc:
            logger.exception("Unhandled Nexus API failure")
            return self._failure(
                APIError("internal_error", str(exc) or type(exc).__name__, status=500)
            )
