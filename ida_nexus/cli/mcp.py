"""IDA Domain Nexus MCP server.

This server exposes a compact Nexus surface for the ida-domain API:
- reference(query): look up the active ida-domain API reference
- open_database(...): attach to a GUI database or shared idalib worker
- execute_python(code): run Python against an already-open database
- list_databases(): discover registered GUI and idalib database instances
- save_database(...): explicitly save an active database
- close_database(...): release this MCP server's handle and lease
"""

import argparse
import asyncio
import atexit
import inspect
import ipaddress
import json
import os
import signal
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import wraps
from importlib.metadata import version
from pathlib import Path
from typing import (
    Annotated,
    Any,
    BinaryIO,
    NoReturn,
    NotRequired,
    ParamSpec,
    TypeVar,
    cast,
)
from urllib.parse import urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

MCP_ENVIRONMENT_VARIABLES = (
    "IDA_NEXUS_ID",
    "IDAUSR",
    "IDA_NEXUS_STATE_DIR",
)


def _unset_empty_environment_variables() -> None:
    """Prevent MCP child processes from inheriting empty overrides."""
    for name in MCP_ENVIRONMENT_VARIABLES:
        if os.environ.get(name) == "":
            del os.environ[name]


from zeromcp import McpServer, McpToolError

from ida_nexus import (
    CloseDatabaseResult,
    DatabaseManager,
    DatabaseSelectionError,
    ListDatabasesResult,
    NexusError,
    OpenDatabaseResult,
    PythonExecutionResult,
    RemoteError,
    SaveDatabaseResult,
    get_ida_domain_version,
    get_state_dir,
)
from ida_nexus import (
    reference as lookup_reference,
)
from ida_nexus.paths import _get_idausr_dir
from ida_nexus.reference import _find_ida_domain_package_path

SESSIONS_DIR = get_state_dir() / "sessions"
OPEN_TIMEOUT_SECONDS = 300
EXECUTE_TIMEOUT_SECONDS = 360

PACKAGE_VERSION = version("ida-nexus")
mcp = McpServer("ida", version=PACKAGE_VERSION)


def _trace_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _trace_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _trace_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_trace_jsonable(item) for item in value]
    return repr(value)


class _TraceLogger:
    """Thread-safe semantic trace created lazily on the first tool call."""

    def __init__(self) -> None:
        self.server_id = uuid.uuid4().hex[:12]
        self.path = SESSIONS_DIR / f"{self.server_id}.jsonl"
        self._lock = threading.Lock()
        self._buffer: list[str] = []
        self._active = False

    def _activate(self, encoded: str) -> None:
        SESSIONS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            SESSIONS_DIR.chmod(0o700)
        except OSError:
            if os.name != "nt":
                raise
        self._append(encoded)

    def _append(self, encoded: str) -> None:
        fd = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as file:
            file.write(encoded)
            file.flush()

    def emit(self, event: str, **fields: Any) -> None:
        record = {
            "schema": 1,
            "ts": datetime.now(UTC).isoformat(),
            "mcp_server_id": self.server_id,
            "pid": os.getpid(),
            "event": event,
            **fields,
        }
        encoded = (
            json.dumps(
                _trace_jsonable(record),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        with self._lock:
            if self._active:
                self._append(encoded)
                return

            self._buffer.append(encoded)
            if event == "tool_call":
                self._activate("".join(self._buffer))
                self._buffer.clear()
                self._active = True
            elif event == "mcp_stopped":
                # A connection that never called a tool leaves no session trace.
                self._buffer.clear()


TRACE = _TraceLogger()
_TRACE_CALL_ID: ContextVar[str | None] = ContextVar(
    "ida_nexus_trace_call_id", default=None
)


def _session_fields_from_meta(meta: dict[str, Any]) -> dict[str, Any]:
    """Retain request metadata for future agent/session integrations."""
    fields = dict(meta)
    # The process environment is authoritative for the Nexus session identity;
    # request metadata must not be able to spoof it.
    fields["nexus_id"] = os.environ.get("IDA_NEXUS_ID") or None
    return fields


def _session_fields() -> dict[str, Any]:
    try:
        meta = mcp.context.meta or {}
    except (AttributeError, LookupError, RuntimeError):
        # Shutdown and asynchronous database events may have no MCP request.
        meta = {}
    return _session_fields_from_meta(meta)


def _install_initialize_trace_adapter() -> None:
    """Record MCP client identity and metadata from the initialize request."""
    original_initialize = mcp.registry.methods["initialize"]

    def initialize_with_trace(
        protocolVersion: str,
        capabilities: dict[str, Any],
        clientInfo: dict[str, Any],
        _meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = original_initialize(protocolVersion, capabilities, clientInfo, _meta)
        TRACE.emit(
            "mcp_initialized",
            session=_session_fields(),
            clientInfo=clientInfo,
            _meta=_meta,
        )
        return result

    mcp.registry.methods["initialize"] = initialize_with_trace


def _install_hook_input_meta_adapter() -> None:
    """Promote metadata embedded in tool arguments into MCP request metadata."""
    original_tools_call = mcp.registry.methods["tools/call"]

    def tools_call_with_meta(
        name: str,
        arguments: dict[str, Any] | None = None,
        _meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        clean_arguments = arguments
        request_meta = dict(_meta) if isinstance(_meta, dict) else {}
        if isinstance(arguments, dict):
            clean_arguments = dict(arguments)
            input_meta = clean_arguments.pop("_meta", None)
            if isinstance(input_meta, dict):
                request_meta.update(input_meta)
        return original_tools_call(name, clean_arguments, request_meta or None)

    mcp.registry.methods["tools/call"] = tools_call_with_meta


_install_initialize_trace_adapter()
_install_hook_input_meta_adapter()


def _error_fields(error: Exception) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "type": type(error).__name__,
        "message": str(error),
        "traceback": traceback.format_exc(),
    }
    if isinstance(error, RemoteError):
        fields.update(
            code=error.code,
            status=error.status,
            details=error.details,
        )
    return fields


def _as_tool_error(error: Exception) -> McpToolError:
    if isinstance(error, McpToolError):
        return error
    if isinstance(error, RemoteError):
        sections = [str(error)]
        for label in ("stdout", "stderr", "traceback"):
            value = error.details.get(label)
            if isinstance(value, str) and value:
                sections.append(f"{label}:\n{value.rstrip()}")
        return McpToolError("\n\n".join(sections))
    if isinstance(error, (NexusError, FileNotFoundError, ValueError)):
        return McpToolError(str(error))
    return McpToolError(str(error) or type(error).__name__)


def _trace_database_event(event: str, fields: dict[str, Any]) -> None:
    fields = dict(fields)
    error = fields.get("error")
    if isinstance(error, Exception):
        fields["error"] = _error_fields(error)
    call_id = _TRACE_CALL_ID.get()
    if call_id is not None:
        fields.setdefault("call_id", call_id)
    TRACE.emit(event, session=_session_fields(), **fields)


DATABASE_MANAGER = DatabaseManager(
    on_event=_trace_database_event,
    open_timeout=OPEN_TIMEOUT_SECONDS,
    execute_timeout=EXECUTE_TIMEOUT_SECONDS,
)

_TRACE_LIFECYCLE_LOCK = threading.Lock()
_TRACE_STARTED = False
_TRACE_STOPPED = False
_OPERATION_LABEL = "ida-nexus mcp"


def _start_mcp_trace(transport: str, agent: str | None) -> None:
    global _OPERATION_LABEL, _TRACE_STARTED
    with _TRACE_LIFECYCLE_LOCK:
        if _TRACE_STARTED:
            return
        _TRACE_STARTED = True
        _OPERATION_LABEL = agent or "ida-nexus mcp"
    TRACE.emit(
        "mcp_started",
        session=_session_fields(),
        transport=transport,
        agent=agent,
        trace_path=str(TRACE.path),
    )


def _shutdown_server_state() -> None:
    global _TRACE_STOPPED
    DATABASE_MANAGER.shutdown()
    with _TRACE_LIFECYCLE_LOCK:
        if not _TRACE_STARTED or _TRACE_STOPPED:
            return
        _TRACE_STOPPED = True
    TRACE.emit("mcp_stopped", session=_session_fields())


atexit.register(_shutdown_server_state)


P = ParamSpec("P")
R = TypeVar("R")


def tool(func: Callable[P, R]) -> Callable[P, R]:
    """Register an MCP tool and trace each invocation."""
    signature = inspect.signature(func)

    def start_trace(
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any], float]:
        name = getattr(func, "__name__", "<unnamed>")
        arguments = signature.bind(*args, **kwargs)
        arguments.apply_defaults()
        call_id = uuid.uuid4().hex
        session = _session_fields()
        TRACE.emit(
            "tool_call",
            call_id=call_id,
            tool=name,
            session=session,
            input=dict(arguments.arguments),
        )
        return name, call_id, session, time.monotonic()

    def trace_error(
        error: Exception,
        name: str,
        call_id: str,
        session: dict[str, Any],
        started: float,
    ) -> NoReturn:
        TRACE.emit(
            "tool_error",
            call_id=call_id,
            tool=name,
            session=session,
            duration_ms=round((time.monotonic() - started) * 1000, 3),
            error=_error_fields(error),
        )
        tool_error = _as_tool_error(error)
        if tool_error is error:
            raise error
        raise tool_error from error

    def trace_result(
        result: Any,
        name: str,
        call_id: str,
        session: dict[str, Any],
        started: float,
    ) -> None:
        TRACE.emit(
            "tool_result",
            call_id=call_id,
            tool=name,
            session=session,
            duration_ms=round((time.monotonic() - started) * 1000, 3),
            output=result,
        )

    if inspect.iscoroutinefunction(func):

        @wraps(func)
        async def traced_async(*args: P.args, **kwargs: P.kwargs) -> Any:
            name, call_id, session, started = start_trace(args, kwargs)
            token = _TRACE_CALL_ID.set(call_id)
            try:
                try:
                    result = await func(*args, **kwargs)
                except asyncio.CancelledError:
                    TRACE.emit(
                        "tool_cancelled",
                        call_id=call_id,
                        tool=name,
                        session=session,
                        duration_ms=round((time.monotonic() - started) * 1000, 3),
                    )
                    raise
                except Exception as error:  # noqa: BLE001 - traced tool boundary
                    trace_error(error, name, call_id, session, started)
                trace_result(result, name, call_id, session, started)
                return result
            finally:
                _TRACE_CALL_ID.reset(token)

        return mcp.tool(traced_async)  # type: ignore[return-value]

    @wraps(func)
    def traced(*args: P.args, **kwargs: P.kwargs) -> R:
        name, call_id, session, started = start_trace(args, kwargs)
        token = _TRACE_CALL_ID.set(call_id)
        try:
            try:
                result = func(*args, **kwargs)
            except Exception as error:  # noqa: BLE001 - traced tool boundary
                trace_error(error, name, call_id, session, started)
            trace_result(result, name, call_id, session, started)
            return result
        finally:
            _TRACE_CALL_ID.reset(token)

    return mcp.tool(traced)


@tool
def reference(
    query: Annotated[
        str,
        "Class, method, or reverse-engineering concept to look up in the IDA reference.",
    ],
) -> str:
    """Look up the active ida-domain API and return a plain-text IDA reference."""

    return lookup_reference(query)


class OpenDatabaseToolResult(OpenDatabaseResult):
    log_path: str
    nexus_id: str | None
    hint: str


@tool
def open_database(
    path: Annotated[
        str,
        "Path to a local executable or IDB. A GUI instance is used when available.",
    ],
    set_current: Annotated[
        bool,
        "Whether this database should become the default target for execute_python().",
    ] = True,
) -> OpenDatabaseToolResult:
    """Attach to a GUI database or shared managed idalib worker through IDA Nexus."""

    result = DATABASE_MANAGER.open_database(path, set_current=set_current)
    session = _session_fields()
    nexus_id = session.get("nexus_id")
    return OpenDatabaseToolResult(
        **result,
        log_path=str(TRACE.path),
        nexus_id=nexus_id if isinstance(nexus_id, str) else None,
        hint=(
            "Call reference(query) to inspect the IDA Domain API before using "
            "execute_python; `db` and `ida_domain` are available globally."
        ),
    )


@tool
async def execute_python(
    code: Annotated[
        str,
        (
            "Python code that runs against an already-open database. Call reference(query) "
            "first; do not guess the API shape. `db` is the current ida-domain Database, "
            "and `ida_domain` is also imported globally. Imports, variables, and "
            "definitions persist for this agent's database lease. A single or trailing "
            "expression is returned. For function-style code, define run(db), "
            "execute(db), or main(db); "
            "it is invoked automatically when there is no trailing expression."
        ),
    ],
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, use the current target.",
    ] = None,
    timeout: Annotated[
        float,
        (
            "Python execution timeout in seconds. This does not include the separate "
            "initial autoanalysis wait."
        ),
    ] = EXECUTE_TIMEOUT_SECONDS,
) -> PythonExecutionResult:
    """Execute Python and return its result plus captured stdout and stderr."""

    # Resolve an omitted current target once so concurrent open_database calls
    # cannot redirect cancellation to another database mid-request.
    target_id = await asyncio.to_thread(
        DATABASE_MANAGER.resolve_instance_id,
        instance_id,
    )
    operation_id = _TRACE_CALL_ID.get() or uuid.uuid4().hex
    cancel_requested = threading.Event()

    def execute() -> PythonExecutionResult:
        DATABASE_MANAGER.ensure_autoanalysis(
            target_id,
            operation_id=operation_id,
        )
        # Analysis and execution are separate HTTP operations. Cancellation may
        # race successful analysis completion, so do not start user code after
        # the encompassing MCP request has been cancelled.
        if cancel_requested.is_set():
            raise DatabaseSelectionError("operation cancelled")
        return DATABASE_MANAGER.execute_python(
            code,
            target_id,
            timeout=timeout,
            operation_id=operation_id,
            operation_label=_OPERATION_LABEL,
            persist_globals=True,
        )

    operation = asyncio.create_task(asyncio.to_thread(execute))
    try:
        return await asyncio.shield(operation)
    except asyncio.CancelledError:
        cancel_requested.set()
        try:
            # Keep cancelling by request-owned id until the composite analysis
            # plus execution task has unwound. A positive acknowledgement may
            # refer to analysis just as execution is about to begin.
            while not operation.done():
                with suppress(Exception):
                    await asyncio.to_thread(
                        DATABASE_MANAGER.cancel_operation,
                        target_id,
                        operation_id,
                    )
                if not operation.done():
                    await asyncio.sleep(0.01)
        finally:
            with suppress(Exception):
                await asyncio.shield(operation)
        raise


def _compatible_gui_plugin(plugin_dir: Path, required_version: str) -> bool:
    """Check one plugin directory for a compatible ida-nexus install."""
    plugin_manifest = plugin_dir / "ida-plugin.json"
    plugin_entrypoint = plugin_dir / "ida_nexus_plugin.py"
    if not plugin_entrypoint.is_file():
        return False

    try:
        document = json.loads(plugin_manifest.read_text(encoding="utf-8"))
        plugin_version = document["plugin"]["version"]
        if not isinstance(plugin_version, str):
            return False
        return Version(plugin_version) >= Version(required_version)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        InvalidVersion,
    ):
        return False


def _declares_nexus_gui_provider(plugin_dir: Path, expected_name: str) -> bool:
    """Check a consumer plugin that delegates to the installed Nexus package."""

    try:
        document = json.loads(
            (plugin_dir / "ida-plugin.json").read_text(encoding="utf-8")
        )
        metadata = document["plugin"]
        if metadata["name"] != expected_name:
            return False
        entry_point = metadata["entryPoint"]
        dependencies = metadata["pythonDependencies"]
        if not isinstance(entry_point, str) or not (plugin_dir / entry_point).is_file():
            return False
        if not isinstance(dependencies, list):
            return False
        return any(
            canonicalize_name(Requirement(dependency).name) == "ida-nexus"
            for dependency in dependencies
            if isinstance(dependency, str)
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        InvalidRequirement,
    ):
        return False


def _gui_plugin_installed() -> bool:
    plugins_dir = _get_idausr_dir() / "plugins"
    if _compatible_gui_plugin(plugins_dir / "ida-nexus", PACKAGE_VERSION):
        return True
    return any(
        _declares_nexus_gui_provider(plugins_dir / name, name)
        for name in ("ida-mcp", "ida-chat")
    )


class ListDatabasesToolResult(ListDatabasesResult):
    hint: NotRequired[str]


@tool
def list_databases() -> ListDatabasesToolResult:
    """Discover registered GUI and idalib databases in IDA Nexus."""
    result = ListDatabasesToolResult(**DATABASE_MANAGER.list_databases())
    if not _gui_plugin_installed():
        result["hint"] = (
            "To enable GUI database discovery: uvx ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus"
        )
    return result


@tool
def save_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, save the current target.",
    ] = None,
) -> SaveDatabaseResult:
    """Explicitly save an active GUI or idalib database."""

    return DATABASE_MANAGER.save_database(instance_id)


@tool
def close_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, release the current target.",
    ] = None,
) -> CloseDatabaseResult:
    """Release this MCP's IDA Nexus database handle without disrupting other clients.

    If this is the final lease on a managed idalib worker, orphaned execution is
    cancelled and this call waits for the IDB to finish closing. GUI databases are
    never closed here.
    """

    return DATABASE_MANAGER.close_database(instance_id)


def _install_server_shutdown_handlers() -> None:
    def cleanup_and_exit(signum: int, _frame: Any) -> None:
        _shutdown_server_state()
        try:
            mcp.stop()
        finally:
            raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)


class _ShutdownOnEOFInput:
    """Trigger lease cleanup as soon as the stdio peer closes its input."""

    def __init__(self, stream: BinaryIO, on_eof: Callable[[], None]) -> None:
        self._stream = stream
        self._on_eof = on_eof
        self._eof_seen = False
        self._lock = threading.Lock()

    def readline(self, size: int = -1) -> bytes:
        data = self._stream.readline(size)
        if data:
            return data
        with self._lock:
            if not self._eof_seen:
                self._eof_seen = True
                self._on_eof()
        return data

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _serve(
    transport: str,
    database: str | None = None,
    agent: str | None = None,
) -> None:
    _unset_empty_environment_variables()
    _install_server_shutdown_handlers()
    _start_mcp_trace(transport, agent)

    if database:
        DATABASE_MANAGER.schedule_startup_open(database)

    if transport == "stdio":
        # ZeroMCP only reads from this transparent proxy, but its public
        # annotation requires the concrete BinaryIO type.
        stdin = cast(
            BinaryIO,
            _ShutdownOnEOFInput(sys.stdin.buffer, _shutdown_server_state),
        )
        try:
            asyncio.run(mcp.stdio_async(stdin=stdin))
        finally:
            _shutdown_server_state()
        return

    url = urlparse(transport)
    if url.hostname is None or url.port is None:
        raise ValueError(f"Invalid transport URL: {transport}")

    try:
        loopback = ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        loopback = url.hostname.casefold() == "localhost"
    if not loopback:
        print(
            "WARNING: MCP HTTP transport is bound to a non-loopback host without "
            "built-in authentication; execute_python may be reachable over the network.",
            file=sys.stderr,
        )

    print("Starting IDA Nexus MCP server...")
    print(
        f"Using ida-domain {get_ida_domain_version()} from {_find_ida_domain_package_path()}"
    )
    print(f"Writing semantic trace to {TRACE.path}")
    print("Available tools:")
    for name, func in mcp.tools.methods.items():
        print(f"  - {name}: {(func.__doc__ or '').strip()}")
    print()

    mcp.serve(url.hostname, url.port)

    try:
        input("Server is running, press Enter or Ctrl+C to stop...")
    except (KeyboardInterrupt, EOFError):
        print("\nStopping server...")
    finally:
        _shutdown_server_state()
        mcp.stop()


def _report_claude_session(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = payload.get("input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    existing_meta = tool_input.get("_meta")
    if not isinstance(existing_meta, dict):
        existing_meta = {}

    transcript_path = payload.get("transcript_path")
    updated_input = dict(tool_input)

    updated_meta = dict(existing_meta)
    if isinstance(transcript_path, str) and transcript_path:
        updated_meta["claude_session_path"] = transcript_path

    if updated_meta:
        updated_input["_meta"] = updated_meta

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated_input,
        }
    }


def _report_codex_session(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = payload.get("input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    existing_meta = tool_input.get("_meta")
    if not isinstance(existing_meta, dict):
        existing_meta = {}

    transcript_path = payload.get("transcript_path")
    updated_input = dict(tool_input)

    updated_meta = dict(existing_meta)
    if isinstance(transcript_path, str) and transcript_path:
        updated_meta["codex_session_path"] = transcript_path

    if updated_meta:
        updated_input["_meta"] = updated_meta

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
        }
    }


def _report_session_main(platform: str) -> int:
    """Inject agent transcript/session metadata into a PreToolUse tool input."""

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"report-session: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 1

    match platform:
        case "claude":
            response = _report_claude_session(payload)
        case "codex":
            response = _report_codex_session(payload)
        case _:
            print(f"report-session: unsupported platform: {platform}", file=sys.stderr)
            return 2

    print(json.dumps(response))
    return 0


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-nexus mcp",
        description="IDA Domain Nexus MCP server",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        help="Transport (stdio or http://host:port). Defaults to stdio.",
    )
    parser.add_argument(
        "--database",
        default=None,
        help="Path to an executable or IDB to open and activate on startup, "
        "so agents don't need to call open_database() first.",
    )
    parser.add_argument(
        "--agent",
        default=None,
        help="Agent name to record in the MCP session trace.",
    )
    parser.add_argument(
        "--report-session",
        choices=["claude", "codex"],
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args(argv)

    if args.report_session is not None:
        return _report_session_main(args.report_session)

    _serve(
        args.transport,
        database=args.database,
        agent=args.agent,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
