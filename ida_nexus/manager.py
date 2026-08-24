"""MCP-agnostic multi-instance database session manager.

The manager owns database discovery, attachment, selection, and lease cleanup.
Protocol adapters may subscribe to domain lifecycle events through ``on_event``;
error presentation, request metadata, and tracing belong to those adapters.
"""

import math
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from ida_nexus._registry import (
    LOG_DIR,
    DatabaseInstance,
    canonical_path,
    idb_key,
    scan_instances,
)
from ida_nexus._resolver import expected_idb_path
from ida_nexus.errors import DatabaseSelectionError, NexusConnectionError
from ida_nexus.handle import DatabaseHandle
from ida_nexus.models import PythonExecutionResult
from ida_nexus.options import MAX_KEEPALIVE_SECONDS, DatabaseOpenOptions

DEFAULT_OPEN_TIMEOUT_SECONDS = 300.0
DEFAULT_EXECUTE_TIMEOUT_SECONDS = 360.0


DatabaseEventCallback = Callable[[str, dict[str, Any]], None]


def _resolve_user_path(path: str) -> str:
    return canonical_path(path)


def _entry_target_fields(entry: DatabaseInstance) -> dict[str, Any]:
    return {
        "record_id": entry.record_id,
        "backend": entry.backend,
        "pid": entry.pid,
        "port": entry.port,
        "idb_path": entry.idb_path,
        "idb_key": entry.idb_key,
        "exe_path": entry.exe_path,
        "managed": entry.managed,
        "started_at": entry.started_at,
        "worker_log_path": (
            str(LOG_DIR / f"{entry.record_id}.log")
            if entry.backend == "idalib"
            else None
        ),
    }


DatabaseStatus = Literal["available", "attached", "current", "unavailable"]


class DatabaseListing(TypedDict):
    path: str
    backend: Annotated[str, "Instance backend: gui or idalib."]
    status: Annotated[
        str,
        "Action state: available, attached, current, or unavailable.",
    ]
    instance_id: str | None
    error: str | None


class ListDatabasesResult(TypedDict):
    instances: list[DatabaseListing]


class OpenDatabaseResult(TypedDict):
    instance_id: str
    backend: Annotated[str, "Instance backend: gui or idalib."]
    status: Annotated[str, "Attachment state: attached or current."]


class WaitAutoanalysisResult(TypedDict):
    status: str
    complete: bool


class SaveDatabaseResult(TypedDict):
    path: str


class CloseDatabaseResult(TypedDict):
    closed: bool


@dataclass(frozen=True)
class _AttachedDatabase:
    entry: DatabaseInstance
    instance_id: str
    current: bool


@dataclass
class _DatabaseSession:
    instance_id: str
    requested_path: str
    handle: DatabaseHandle
    autoanalysis_complete: bool = False


class DatabaseManager:
    def __init__(
        self,
        *,
        on_event: DatabaseEventCallback | None = None,
        open_timeout: float = DEFAULT_OPEN_TIMEOUT_SECONDS,
        execute_timeout: float = DEFAULT_EXECUTE_TIMEOUT_SECONDS,
        keepalive: float = 0.0,
    ) -> None:
        if not math.isfinite(open_timeout) or open_timeout <= 0:
            raise ValueError("open_timeout must be a positive finite number")
        if not math.isfinite(execute_timeout) or execute_timeout <= 0:
            raise ValueError("execute_timeout must be a positive finite number")
        if (
            not math.isfinite(keepalive)
            or keepalive < 0
            or keepalive > MAX_KEEPALIVE_SECONDS
        ):
            raise ValueError(
                f"keepalive must be between 0 and {MAX_KEEPALIVE_SECONDS:g} seconds"
            )
        self._on_event = on_event
        self._open_timeout = open_timeout
        self._execute_timeout = execute_timeout
        self._keepalive = float(keepalive)
        self._instances: dict[str, _DatabaseSession] = {}
        self._disconnected_instances: dict[str, str] = {}
        self._disconnected_default: str | None = None
        self._current_instance_id: str | None = None
        self._lock = threading.RLock()
        self._open_lock = threading.Lock()
        self._shutdown_started = False
        # Background thread from a scheduled startup open, if any. Operations
        # that need the current database wait on it so they do not race the
        # deliberately non-blocking attachment.
        self._startup_open_thread: threading.Thread | None = None

    def _emit(self, event: str, **fields: Any) -> None:
        if self._on_event is not None:
            self._on_event(event, fields)

    def _database_info(self, session: _DatabaseSession) -> dict[str, Any]:
        return {
            "instance_id": session.instance_id,
            "requested_path": session.requested_path,
            **_entry_target_fields(session.handle.instance),
        }

    def _handle_disconnected(self, handle: DatabaseHandle, reason: str) -> None:
        with self._lock:
            session = next(
                (
                    candidate
                    for candidate in self._instances.values()
                    if candidate.handle is handle
                ),
                None,
            )
            if session is None:
                return
            self._instances.pop(session.instance_id, None)
            self._disconnected_instances[session.instance_id] = reason
            if self._current_instance_id == session.instance_id:
                self._current_instance_id = None
                self._disconnected_default = session.instance_id
        self._emit(
            "database_disconnected",
            instance_id=session.instance_id,
            target=self._database_info(session),
            reason=reason,
        )

    def open_database(self, path: str, *, set_current: bool) -> OpenDatabaseResult:
        # Do NOT require the path to exist on disk here. A live instance (e.g. an
        # unsaved GUI database whose .i64 has not been written yet) may be
        # registered for this path; resolve_instance matches the registry first
        # and only needs a real file when it must spawn a worker (where it
        # raises FileNotFoundError for the caller or protocol adapter to present).
        resolved_path = _resolve_user_path(path)

        # Serialize local opens so duplicate calls create at most one retained
        # lease in this manager. Other managers retain their own leases.
        with self._open_lock:
            with self._lock:
                if self._shutdown_started:
                    raise DatabaseSelectionError("database manager is shutting down")
                candidate = next(
                    (
                        session
                        for session in self._instances.values()
                        if session.requested_path == resolved_path
                        and session.handle.connected
                    ),
                    None,
                )

            existing: _DatabaseSession | None = None
            current: str | None = None
            if candidate is not None:
                with self._lock:
                    if self._instances.get(candidate.instance_id) is candidate:
                        existing = candidate
                        if set_current or self._current_instance_id is None:
                            self._current_instance_id = candidate.instance_id
                            self._disconnected_default = None
                        current = self._current_instance_id

            if existing is None:
                handle = DatabaseHandle.open(
                    resolved_path,
                    options=DatabaseOpenOptions(
                        startup_timeout=self._open_timeout,
                        keepalive=self._keepalive,
                        # Publish the worker first, then start analysis through
                        # its normal Nexus operation and hook lifecycle.
                        auto_analysis=True,
                    ),
                )
                if not handle.connected:
                    reason = handle.disconnect_reason or "database connection closed"
                    handle.close()
                    raise DatabaseSelectionError(
                        f"database disconnected while opening: {reason}"
                    )
                entry = handle.instance
                with self._lock:
                    # shutdown() may have run while DatabaseHandle.open() was
                    # resolving or establishing its lease. Never install a
                    # handle after shutdown has cleared the manager.
                    shutting_down = self._shutdown_started
                    if shutting_down:
                        existing = None
                    else:
                        existing = next(
                            (
                                session
                                for session in self._instances.values()
                                if session.handle.connected
                                and session.handle.instance.record_id == entry.record_id
                            ),
                            None,
                        )
                        if existing is not None:
                            if set_current or self._current_instance_id is None:
                                self._current_instance_id = existing.instance_id
                                self._disconnected_default = None
                            current = self._current_instance_id
                        else:
                            instance_id = uuid.uuid4().hex[:12]
                            existing = _DatabaseSession(
                                instance_id=instance_id,
                                requested_path=resolved_path,
                                handle=handle,
                            )
                            self._instances[instance_id] = existing
                            if set_current or self._current_instance_id is None:
                                self._current_instance_id = instance_id
                                self._disconnected_default = None
                            current = self._current_instance_id

                if shutting_down:
                    handle.close()
                    raise DatabaseSelectionError("database manager is shutting down")
                assert existing is not None
                if existing.handle is not handle:
                    handle.close()
                    event = "database_reused"
                else:
                    handle.set_disconnect_callback(self._handle_disconnected)
                    if not handle.connected:
                        reason = (
                            handle.disconnect_reason or "database connection closed"
                        )
                        raise DatabaseSelectionError(
                            f"database disconnected while opening: {reason}"
                        )
                    event = "database_opened"
            else:
                event = "database_reused"

            self._emit(
                event,
                instance_id=existing.instance_id,
                target=self._database_info(existing),
            )
            return OpenDatabaseResult(
                instance_id=existing.instance_id,
                backend=existing.handle.instance.backend,
                status="current" if current == existing.instance_id else "attached",
            )

    @staticmethod
    def _disconnected_error(instance_id: str) -> DatabaseSelectionError:
        return DatabaseSelectionError(
            f"database instance {instance_id} disconnected since it was last used "
            "and is no longer valid; call list_databases() and open_database() again"
        )

    def schedule_startup_open(self, path: str) -> None:
        """Open and activate a database in a background thread.

        Opening may spawn a managed idalib worker, so startup consumers can use
        this without blocking their own initialization. Operations that need the
        current database wait through ``_await_startup_open`` instead of racing
        the background attachment.
        """
        import sys

        def _open() -> None:
            try:
                self.open_database(path, set_current=True)
                print(f"Startup database ready: {path}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001 - report and let agents retry
                print(f"Startup open failed for {path!r}: {exc}", file=sys.stderr)

        thread = threading.Thread(target=_open, name="startup-open", daemon=True)
        self._startup_open_thread = thread
        thread.start()

    def _await_startup_open(self) -> None:
        """Block until an in-flight startup open finishes (success or failure).

        Called with no locks held: the startup thread's open_database() takes
        ``self._lock`` / ``self._open_lock``, so joining while holding either
        would deadlock. Bounded by the same budget a single open is allowed.
        """
        thread = self._startup_open_thread
        if thread is not None and thread.is_alive():
            thread.join(self._open_timeout)

    def _resolve_target_id(self, instance_id: str | None) -> str | None:
        with self._lock:
            return (
                instance_id or self._current_instance_id or self._disconnected_default
            )

    def _get_session(self, instance_id: str | None) -> tuple[str, _DatabaseSession]:
        target_id = self._resolve_target_id(instance_id)
        if target_id is None:
            # A scheduled startup open may still be attaching in the background.
            # Wait for it, then look again, so the first operation does not
            # spuriously see "no open database".
            self._await_startup_open()
            target_id = self._resolve_target_id(instance_id)
        if target_id is None:
            raise DatabaseSelectionError(
                "no open database instance; call open_database() first"
            )
        with self._lock:
            session = self._instances.get(target_id)
            disconnected = self._disconnected_instances.get(target_id)
        if session is None and disconnected is not None:
            raise self._disconnected_error(target_id)
        if session is None:
            raise DatabaseSelectionError(f"unknown database instance: {target_id}")
        return target_id, session

    def resolve_instance_id(self, instance_id: str | None) -> str:
        """Resolve and pin an optional current target to one attached instance."""
        target_id, session = self._get_session(instance_id)
        if not session.handle.connected:
            raise self._disconnected_error(target_id)
        return target_id

    def ensure_autoanalysis(
        self,
        instance_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> None:
        """Wait once for initial analysis without consuming execution timeout."""
        target_id, session = self._get_session(instance_id)
        if session.autoanalysis_complete:
            return
        result = self.wait_autoanalysis(target_id, operation_id=operation_id)
        if not result["complete"]:
            raise DatabaseSelectionError(
                "autoanalysis did not complete; Python was not executed"
            )

    def execute_python(
        self,
        code: str,
        instance_id: str | None,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> PythonExecutionResult:
        effective_timeout = self._execute_timeout if timeout is None else timeout
        if (
            isinstance(effective_timeout, bool)
            or not isinstance(effective_timeout, (int, float))
            or not math.isfinite(effective_timeout)
            or effective_timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        target_id, session = self._get_session(instance_id)
        if not session.handle.connected:
            raise self._disconnected_error(target_id)
        try:
            return session.handle.execute_python(
                code,
                timeout=float(effective_timeout),
                operation_id=operation_id,
                operation_label=operation_label,
                persist_globals=persist_globals,
                filename=filename,
            )
        except NexusConnectionError:
            if not session.handle.connected:
                raise self._disconnected_error(target_id) from None
            raise

    def cancel_operation(self, instance_id: str, operation_id: str) -> bool:
        """Cancel one request-owned operation without releasing its lease."""
        target_id, session = self._get_session(instance_id)
        if not session.handle.connected:
            raise self._disconnected_error(target_id)
        return session.handle.cancel_operation(operation_id)

    def cancel_active(self, instance_id: str | None) -> bool:
        """Cancel the selected handle's operation without releasing its lease."""
        target_id, session = self._get_session(instance_id)
        if not session.handle.connected:
            raise self._disconnected_error(target_id)
        return session.handle.cancel_active()

    def wait_autoanalysis(
        self,
        instance_id: str | None,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
    ) -> WaitAutoanalysisResult:
        target_id, session = self._get_session(instance_id)
        if not session.handle.connected:
            raise self._disconnected_error(target_id)
        try:
            result = session.handle.wait_autoanalysis(
                timeout,
                operation_id=operation_id,
            )
        except NexusConnectionError:
            if not session.handle.connected:
                raise self._disconnected_error(target_id) from None
            raise
        complete = bool(result["complete"])
        if complete:
            session.autoanalysis_complete = True
        return WaitAutoanalysisResult(
            status=str(result["status"]),
            complete=complete,
        )

    def save_database(self, instance_id: str | None) -> SaveDatabaseResult:
        target_id, session = self._get_session(instance_id)
        if not session.handle.connected:
            raise self._disconnected_error(target_id)
        try:
            result = session.handle.save_database()
        except NexusConnectionError:
            if not session.handle.connected:
                raise self._disconnected_error(target_id) from None
            raise
        self._emit(
            "database_saved",
            instance_id=target_id,
            target=self._database_info(session),
            result=result,
        )
        path = result.get("idb_path")
        if not isinstance(path, str):
            raise DatabaseSelectionError("save_database returned an invalid path")
        return SaveDatabaseResult(path=path)

    @staticmethod
    def _listing_path(entry: DatabaseInstance) -> str:
        """Return a path that open_database() can use to reach this instance."""
        if (
            entry.exe_path
            and Path(entry.exe_path).exists()
            and (
                entry.backend == "gui"
                or idb_key(expected_idb_path(entry.exe_path)) == entry.idb_key
            )
        ):
            return entry.exe_path
        return entry.idb_path

    def list_databases(self) -> ListDatabasesResult:
        with self._lock:
            sessions = list(self._instances.values())
            current = self._current_instance_id

        attached: dict[str, _AttachedDatabase] = {}
        for session in sessions:
            entry = session.handle.instance
            attached[entry.record_id] = _AttachedDatabase(
                entry=entry,
                instance_id=session.instance_id,
                current=session.instance_id == current,
            )

        instances: list[DatabaseListing] = []
        for discovered in scan_instances():
            entry = discovered.instance
            local = attached.pop(entry.record_id, None)
            if discovered.state.value != "ready":
                status: DatabaseStatus = "unavailable"
            elif local is None:
                status = "available"
            elif local.current:
                status = "current"
            else:
                status = "attached"
            instances.append(
                DatabaseListing(
                    path=self._listing_path(entry),
                    backend=entry.backend,
                    status=status,
                    instance_id=local.instance_id if local else None,
                    error=discovered.detail if status == "unavailable" else None,
                )
            )

        # A local lease remains actionable during a transient registry scan,
        # so do not hide it merely because discovery missed its record.
        for local in attached.values():
            instances.append(
                DatabaseListing(
                    path=self._listing_path(local.entry),
                    backend=local.entry.backend,
                    status="current" if local.current else "attached",
                    instance_id=local.instance_id,
                    error=None,
                )
            )

        status_order = {"current": 0, "attached": 1, "available": 2, "unavailable": 3}
        instances.sort(
            key=lambda item: (
                status_order[item["status"]],
                item["backend"] != "gui",
                item["path"],
            )
        )
        return {"instances": instances}

    def close_database(self, instance_id: str | None) -> CloseDatabaseResult:
        target_id, session = self._get_session(instance_id)
        database = self._database_info(session)
        with self._lock:
            current_session = self._instances.get(target_id)
            if current_session is not session:
                raise DatabaseSelectionError(f"unknown database instance: {target_id}")
            self._instances.pop(target_id)
            if self._current_instance_id == target_id:
                self._current_instance_id = next(iter(self._instances), None)
        # Do not take the operation lock: releasing the lease asks the worker to
        # cancel orphaned execution. If this commits final managed shutdown,
        # wait for the lifetime lock released after the IDB has finished closing.
        session.handle.close(wait_for_database=True)
        self._emit(
            "database_released",
            instance_id=target_id,
            target=database,
        )
        return CloseDatabaseResult(closed=True)

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown_started:
                return
            self._shutdown_started = True
            sessions = list(self._instances.values())
            self._instances.clear()
            self._disconnected_instances.clear()
            self._disconnected_default = None
            self._current_instance_id = None
        for session in sessions:
            try:
                session.handle.close()
            except Exception as error:  # noqa: BLE001 -- best-effort shutdown reporting
                self._emit(
                    "database_release_error",
                    instance_id=session.instance_id,
                    error=error,
                )
