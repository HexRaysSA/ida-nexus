#!/usr/bin/env python3
"""Run the real IDA Code Mode MCP surface with timed fake databases.

This is a model-behavior test harness. It is launched instead of
``ida-codemode-mcp`` and never discovers, starts, imports, or connects to IDA.
Scenario files live outside the model's executable workspace under
``<state-dir>/scenarios``. Each file is named ``<executable-name>.json`` by
default; for example, ``samples/foo.exe`` uses
``<state-dir>/scenarios/foo.exe.json``:

    {
      "open_time": 0.5,
      "analysis_time": 90.0
    }

``open_time`` delays ``open_database``. ``analysis_time`` delays the first
``execute_python`` call for that open instance, matching the MCP adapter's
initial-autoanalysis policy. Times are finite non-negative seconds. Optional
``execute_time``, ``result``, ``stdout``, and ``stderr`` fields control the fake
execution after analysis.

Use a unique --state-dir for every run. Semantic traces are written by the real
MCP trace logger under ``<state-dir>/sessions``. The harness writes clearly
marked placeholder ``.i64`` files next to executables after a successful open.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast


@dataclass(frozen=True)
class ExecutableScenario:
    config_path: Path
    open_time: float
    analysis_time: float
    execute_time: float
    result: Any
    stdout: str
    stderr: str


@dataclass
class FakeDatabaseSession:
    instance_id: str
    requested_path: str
    executable_path: str
    idb_path: str
    scenario: ExecutableScenario
    opened_at: float
    autoanalysis_complete: bool = False
    operation_lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )


class FakeDatabaseManager:
    """In-memory DatabaseManager substitute retaining MCP cancellation behavior."""

    def __init__(
        self,
        *,
        scenario_dir: Path,
        config_suffix: str,
        open_timeout: float,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.scenario_dir = scenario_dir
        self.config_suffix = config_suffix
        self.open_timeout = open_timeout
        self._on_event = on_event
        self._instances: dict[str, FakeDatabaseSession] = {}
        self._path_instances: dict[str, str] = {}
        self._current_instance_id: str | None = None
        self._operations: dict[tuple[str, str], threading.Event] = {}
        self._lock = threading.RLock()
        self._open_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._startup_open_thread: threading.Thread | None = None

    @staticmethod
    def _database_error(message: str) -> Exception:
        # Imported lazily so --state-dir is installed before any ida_codemode
        # module snapshots its state paths.
        from ida_codemode.database import DatabaseError

        return DatabaseError(message)

    @staticmethod
    def _remote_timeout(kind: str, timeout: float) -> Exception:
        from ida_codemode.client import RemoteError

        return RemoteError(
            "operation_timeout",
            f"{kind} timed out after {timeout:.2f}s",
            408,
        )

    def _emit(self, event: str, **fields: Any) -> None:
        if self._on_event is not None:
            self._on_event(event, fields)

    @staticmethod
    def _canonical(path: str | os.PathLike[str]) -> str:
        return os.path.realpath(os.path.abspath(os.path.expanduser(os.fspath(path))))

    def _config_path(self, requested_path: str) -> Path:
        source_name = Path(requested_path).name
        candidates = [self.scenario_dir / f"{source_name}{self.config_suffix}"]
        if requested_path.lower().endswith(".i64"):
            executable_name = source_name[:-4]
            candidates.append(
                self.scenario_dir / f"{executable_name}{self.config_suffix}"
            )
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        rendered = " or ".join(str(candidate) for candidate in candidates)
        raise self._database_error(
            f"fake database scenario not found; expected {rendered}"
        )

    @staticmethod
    def _duration(
        document: dict[str, Any],
        name: str,
        *,
        default: float | None = None,
    ) -> float:
        value = document.get(name, default)
        if value is None:
            raise ValueError(f"scenario field {name!r} is required")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError(
                f"scenario field {name!r} must be a finite non-negative number"
            )
        return float(value)

    def _load_scenario(self, requested_path: str) -> ExecutableScenario:
        config_path = self._config_path(requested_path)
        try:
            document = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise self._database_error(
                f"could not read fake database scenario {config_path}: {error}"
            ) from error
        if not isinstance(document, dict):
            raise self._database_error(
                f"fake database scenario {config_path} must be a JSON object"
            )
        try:
            open_time = self._duration(document, "open_time")
            analysis_time = self._duration(document, "analysis_time")
            execute_time = self._duration(document, "execute_time", default=0.0)
            stdout = document.get("stdout", "")
            stderr = document.get("stderr", "")
            if not isinstance(stdout, str) or not isinstance(stderr, str):
                raise TypeError("scenario fields 'stdout' and 'stderr' must be strings")
        except (TypeError, ValueError) as error:
            raise self._database_error(
                f"invalid fake database scenario {config_path}: {error}"
            ) from error
        return ExecutableScenario(
            config_path=config_path,
            open_time=open_time,
            analysis_time=analysis_time,
            execute_time=execute_time,
            result=document.get("result"),
            stdout=stdout,
            stderr=stderr,
        )

    @staticmethod
    def _paths(requested_path: str) -> tuple[str, str]:
        if requested_path.lower().endswith(".i64"):
            executable = requested_path[:-4]
            if not Path(executable).exists():
                executable = ""
            return executable, requested_path
        return requested_path, requested_path + ".i64"

    @staticmethod
    def _fake_idb_document(session: FakeDatabaseSession) -> dict[str, Any]:
        return {
            "fake_ida_codemode_idb": True,
            "executable_path": session.executable_path,
            "idb_path": session.idb_path,
            "instance_id": session.instance_id,
            "scenario_path": str(session.scenario.config_path),
        }

    def _materialize_fake_idb(self, session: FakeDatabaseSession) -> None:
        idb_path = Path(session.idb_path)
        if idb_path.exists():
            # Never replace a real IDB. Existing fake markers are safe to refresh.
            try:
                existing = json.loads(idb_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                return
            if not (
                isinstance(existing, dict)
                and existing.get("fake_ida_codemode_idb") is True
            ):
                return
        idb_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = idb_path.with_name(f".{idb_path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(self._fake_idb_document(session), indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, idb_path)

    def _target(self, session: FakeDatabaseSession) -> dict[str, Any]:
        return {
            "instance_id": session.instance_id,
            "requested_path": session.requested_path,
            "record_id": f"fake-{session.instance_id}",
            "backend": "idalib",
            "pid": os.getpid(),
            "port": 0,
            "idb_path": session.idb_path,
            "idb_key": f"fake-{session.instance_id}",
            "exe_path": session.executable_path,
            "managed": True,
            "started_at": session.opened_at,
            "worker_log_path": None,
            "fake": True,
            "scenario_path": str(session.scenario.config_path),
            "open_time": session.scenario.open_time,
            "analysis_time": session.scenario.analysis_time,
        }

    def _wait_open(self, seconds: float, requested_path: str) -> None:
        allowed = min(seconds, self.open_timeout)
        if self._shutdown.wait(allowed):
            raise self._database_error("database manager is shutting down")
        if seconds > self.open_timeout:
            raise self._database_error(
                f"timed out opening fake database {requested_path} "
                f"after {self.open_timeout:.2f}s"
            )

    def open_database(self, path: str, *, set_current: bool) -> dict[str, Any]:
        requested_path = self._canonical(path)
        with self._open_lock:
            with self._lock:
                if self._shutdown.is_set():
                    raise self._database_error("database manager is shutting down")
                existing_id = self._path_instances.get(requested_path)
                existing = self._instances.get(existing_id) if existing_id else None
                if existing is not None:
                    if set_current or self._current_instance_id is None:
                        self._current_instance_id = existing.instance_id
                    current = self._current_instance_id
                    self._emit(
                        "database_reused",
                        instance_id=existing.instance_id,
                        target=self._target(existing),
                    )
                    return {
                        "instance_id": existing.instance_id,
                        "backend": "idalib",
                        "status": (
                            "current" if current == existing.instance_id else "attached"
                        ),
                    }

            if not Path(requested_path).is_file():
                raise FileNotFoundError(requested_path)
            scenario = self._load_scenario(requested_path)
            self._emit(
                "fake_database_open_wait_started",
                requested_path=requested_path,
                scenario_path=str(scenario.config_path),
                open_time=scenario.open_time,
            )
            self._wait_open(scenario.open_time, requested_path)
            executable_path, idb_path = self._paths(requested_path)
            session = FakeDatabaseSession(
                instance_id=uuid.uuid4().hex[:12],
                requested_path=requested_path,
                executable_path=executable_path,
                idb_path=idb_path,
                scenario=scenario,
                opened_at=time.time(),
            )
            with self._lock:
                if self._shutdown.is_set():
                    raise self._database_error("database manager is shutting down")
                self._instances[session.instance_id] = session
                self._path_instances[requested_path] = session.instance_id
                if set_current or self._current_instance_id is None:
                    self._current_instance_id = session.instance_id
                current = self._current_instance_id
            self._materialize_fake_idb(session)
            self._emit(
                "database_opened",
                instance_id=session.instance_id,
                target=self._target(session),
            )
            return {
                "instance_id": session.instance_id,
                "backend": "idalib",
                "status": ("current" if current == session.instance_id else "attached"),
            }

    def schedule_startup_open(self, path: str) -> None:
        def open_in_background() -> None:
            try:
                self.open_database(path, set_current=True)
                print(f"Fake startup database ready: {path}", file=sys.stderr)
            except Exception as error:  # noqa: BLE001 - startup reports and continues
                print(
                    f"Fake startup open failed for {path!r}: {error}", file=sys.stderr
                )

        thread = threading.Thread(
            target=open_in_background,
            name="fake-startup-open",
            daemon=True,
        )
        self._startup_open_thread = thread
        thread.start()

    def _await_startup_open(self) -> None:
        thread = self._startup_open_thread
        if thread is not None and thread.is_alive():
            thread.join(self.open_timeout)

    def _get_session(self, instance_id: str | None) -> FakeDatabaseSession:
        with self._lock:
            target_id = instance_id or self._current_instance_id
        if target_id is None:
            self._await_startup_open()
            with self._lock:
                target_id = instance_id or self._current_instance_id
        if target_id is None:
            raise self._database_error(
                "no open database instance; call open_database() first"
            )
        with self._lock:
            session = self._instances.get(target_id)
        if session is None:
            raise self._database_error(f"unknown database instance: {target_id}")
        return session

    def resolve_instance_id(self, instance_id: str | None) -> str:
        return self._get_session(instance_id).instance_id

    def _operation_event(
        self,
        session: FakeDatabaseSession,
        operation_id: str | None,
    ) -> threading.Event:
        if operation_id is None:
            return threading.Event()
        key = (session.instance_id, operation_id)
        with self._lock:
            return self._operations.setdefault(key, threading.Event())

    def _finish_operation(
        self,
        session: FakeDatabaseSession,
        operation_id: str | None,
    ) -> None:
        if operation_id is None:
            return
        with self._lock:
            self._operations.pop((session.instance_id, operation_id), None)

    def _wait_operation(
        self,
        seconds: float,
        cancelled: threading.Event,
        *,
        kind: str,
        timeout: float | None = None,
    ) -> None:
        started = time.monotonic()
        completion_deadline = started + seconds
        timeout_deadline = None if timeout is None else started + timeout
        while True:
            if cancelled.is_set() or self._shutdown.is_set():
                raise self._database_error("operation cancelled")
            now = time.monotonic()
            if timeout_deadline is not None and now >= timeout_deadline:
                assert timeout is not None
                raise self._remote_timeout(kind, timeout)
            if now >= completion_deadline:
                return
            remaining = completion_deadline - now
            if timeout_deadline is not None:
                remaining = min(remaining, timeout_deadline - now)
            cancelled.wait(min(0.05, max(0.0, remaining)))

    def ensure_autoanalysis(
        self,
        instance_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> None:
        session = self._get_session(instance_id)
        cancelled = self._operation_event(session, operation_id)
        try:
            with session.operation_lock:
                if cancelled.is_set():
                    raise self._database_error("operation cancelled")
                if session.autoanalysis_complete:
                    return
                self._emit(
                    "fake_autoanalysis_started",
                    instance_id=session.instance_id,
                    operation_id=operation_id,
                    target=self._target(session),
                    analysis_time=session.scenario.analysis_time,
                )
                self._wait_operation(
                    session.scenario.analysis_time,
                    cancelled,
                    kind="analysis",
                )
                session.autoanalysis_complete = True
                self._emit(
                    "fake_autoanalysis_completed",
                    instance_id=session.instance_id,
                    operation_id=operation_id,
                    target=self._target(session),
                )
        except Exception:
            self._finish_operation(session, operation_id)
            raise

    def execute_python(
        self,
        code: str,
        instance_id: str | None,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        session = self._get_session(instance_id)
        cancelled = self._operation_event(session, operation_id)
        try:
            with session.operation_lock:
                self._wait_operation(
                    session.scenario.execute_time,
                    cancelled,
                    kind="execute",
                    timeout=timeout,
                )
                self._emit(
                    "fake_python_executed",
                    instance_id=session.instance_id,
                    operation_id=operation_id,
                    target=self._target(session),
                    code=code,
                )
                result = session.scenario.result
                if result is None:
                    result = {
                        "fake": True,
                        "executable_path": session.executable_path,
                        "idb_path": session.idb_path,
                    }
                return {
                    "result": result,
                    "stdout": session.scenario.stdout,
                    "stderr": session.scenario.stderr,
                }
        finally:
            self._finish_operation(session, operation_id)

    def cancel_operation(self, instance_id: str, operation_id: str) -> bool:
        session = self._get_session(instance_id)
        with self._lock:
            cancelled = self._operations.get((session.instance_id, operation_id))
        if cancelled is None:
            return False
        cancelled.set()
        self._emit(
            "fake_operation_cancel_requested",
            instance_id=session.instance_id,
            operation_id=operation_id,
            target=self._target(session),
        )
        return True

    def list_databases(self) -> dict[str, Any]:
        with self._lock:
            sessions = list(self._instances.values())
            current = self._current_instance_id
        instances = [
            {
                "path": session.executable_path or session.idb_path,
                "backend": "idalib",
                "status": ("current" if session.instance_id == current else "attached"),
                "instance_id": session.instance_id,
                "error": None,
            }
            for session in sessions
        ]
        instances.sort(
            key=lambda item: (item["status"] != "current", str(item["path"]))
        )
        return {"instances": instances}

    def save_database(self, instance_id: str | None) -> dict[str, str]:
        session = self._get_session(instance_id)
        with session.operation_lock:
            self._materialize_fake_idb(session)
        result = {"path": session.idb_path}
        self._emit(
            "database_saved",
            instance_id=session.instance_id,
            target=self._target(session),
            result={"saved": True, "idb_path": session.idb_path},
        )
        return result

    def close_database(self, instance_id: str | None) -> dict[str, bool]:
        session = self._get_session(instance_id)
        with self._lock:
            current = self._instances.get(session.instance_id)
            if current is not session:
                raise self._database_error(
                    f"unknown database instance: {session.instance_id}"
                )
            self._instances.pop(session.instance_id)
            self._path_instances.pop(session.requested_path, None)
            for key, cancelled in list(self._operations.items()):
                if key[0] == session.instance_id:
                    cancelled.set()
                    self._operations.pop(key, None)
            if self._current_instance_id == session.instance_id:
                self._current_instance_id = next(iter(self._instances), None)
        self._materialize_fake_idb(session)
        self._emit(
            "database_released",
            instance_id=session.instance_id,
            target=self._target(session),
        )
        return {"closed": True}

    def shutdown(self) -> None:
        if self._shutdown.is_set():
            return
        self._shutdown.set()
        with self._lock:
            sessions = list(self._instances.values())
            for cancelled in self._operations.values():
                cancelled.set()
            self._operations.clear()
            self._instances.clear()
            self._path_instances.clear()
            self._current_instance_id = None
        for session in sessions:
            self._materialize_fake_idb(session)
            self._emit(
                "database_released",
                instance_id=session.instance_id,
                target=self._target(session),
            )


def _positive_finite(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run IDA Code Mode MCP against timed fake executable scenarios."
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        help="Transport (stdio or http://host:port). Defaults to stdio.",
    )
    parser.add_argument(
        "--database",
        help="Optionally schedule one fake executable to open at startup.",
    )
    parser.add_argument("--agent", help="Agent name recorded in the MCP trace.")
    parser.add_argument(
        "--state-dir",
        type=Path,
        help=(
            "Isolated Code Mode state directory. Required unless "
            "IDA_CODEMODE_STATE_DIR is already set."
        ),
    )
    parser.add_argument(
        "--config-suffix",
        default=".json",
        help=(
            "Scenario filename suffix under <state-dir>/scenarios. "
            "Defaults to .json (foo.exe.json)."
        ),
    )
    parser.add_argument(
        "--open-timeout",
        type=_positive_finite,
        default=300.0,
        help="Maximum fake open wait in seconds. Defaults to 300.",
    )
    parser.add_argument(
        "--install-plugin",
        action="store_true",
        help="Accepted for MCP-config compatibility but always ignored.",
    )
    parser.add_argument(
        "--report-session",
        choices=["claude", "codex"],
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    if not args.config_suffix:
        parser.error("--config-suffix must not be empty")
    if args.state_dir is None and not os.environ.get("IDA_CODEMODE_STATE_DIR"):
        parser.error(
            "--state-dir or IDA_CODEMODE_STATE_DIR is required so fake runs cannot "
            "touch live Code Mode state"
        )
    return args


def _install_isolated_environment(args: argparse.Namespace) -> Path:
    raw_state_dir = (
        args.state_dir
        if args.state_dir is not None
        else Path(os.environ["IDA_CODEMODE_STATE_DIR"])
    )
    state_dir = raw_state_dir.expanduser().resolve()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.environ["IDA_CODEMODE_STATE_DIR"] = str(state_dir)
    # The fake server never installs a plugin, but isolating IDAUSR also keeps
    # plugin discovery and any accidentally inherited tooling away from live IDA.
    os.environ["IDAUSR"] = str(state_dir / "idausr")
    return state_dir


def main() -> int:
    args = _parse_args()
    state_dir = _install_isolated_environment(args)

    # Imports must follow environment installation: Code Mode snapshots all
    # registry, log, and semantic-session paths at import time.
    import ida_codemode_mcp as mcp_app

    if args.report_session is not None:
        return mcp_app._report_session_main(args.report_session)

    scenario_dir = state_dir / "scenarios"
    scenario_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    manager = FakeDatabaseManager(
        scenario_dir=scenario_dir,
        config_suffix=args.config_suffix,
        open_timeout=args.open_timeout,
        on_event=mcp_app._trace_database_event,
    )
    # The production manager has not opened anything, but shutting it down makes
    # replacement explicit and keeps future constructor side effects harmless.
    mcp_app.DATABASE_MANAGER.shutdown()
    mcp_app.DATABASE_MANAGER = cast(Any, manager)
    # Suppress the real-GUI installation hint; installing a plugin would defeat
    # the isolation guarantee and is irrelevant to this fake registry.
    mcp_app._gui_plugin_installed = cast(Any, lambda: True)

    if args.install_plugin:
        print(
            "fake IDA MCP: ignoring --install-plugin; no IDA integration is used",
            file=sys.stderr,
        )
    print(
        f"fake IDA MCP: state={state_dir}, scenarios={scenario_dir}, "
        f"config_suffix={args.config_suffix!r}",
        file=sys.stderr,
    )
    mcp_app._serve(
        args.transport,
        database=args.database,
        agent=args.agent,
        install_plugin=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
