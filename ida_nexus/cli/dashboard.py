"""Web dashboard for ida-nexus semantic sessions.

Serves a local HTTP UI (stdlib only, no extra dependencies) that lists the
JSONL traces under ``<IDAUSR>/nexus/sessions`` and renders each MCP/agent
session as a timeline linked to its agent transcript.

Run with: ida-nexus dashboard [--host 127.0.0.1] [--port 8736] [--open]
"""

import argparse
import html
import ipaddress
import json
import os
import re
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from ida_nexus.cli.logs import (
    LogArchiveError,
    iter_agent_session_paths,
    open_log_archive,
)
from ida_nexus.paths import STATE_DIR

DEFAULT_SESSIONS_DIR = STATE_DIR / "sessions"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8736

SESSIONS_DIR = DEFAULT_SESSIONS_DIR
ARCHIVE_PATH: Path | None = None
ARCHIVE_PATH_MAP: dict[str, Path] = {}
ARCHIVE_SESSION_AGENT_PATHS: dict[tuple[str, str], str] = {}
ARCHIVE_SOURCE_PATHS: dict[Path, str] = {}

_MIN_DT = datetime.min.replace(tzinfo=UTC)


# --------------------------------------------------------------------------
# JSONL helpers
# --------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except OSError:
        pass
    return records


def _parse_ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _format_ts(dt: datetime | None, with_date: bool = True) -> str:
    if dt is None:
        return ""
    local = dt.astimezone()
    return local.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs:02d}s"


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _format_tokens(n: int) -> str:
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    return f"{n / 1_000_000:.2f}M"


def _format_cost(cost: float) -> str:
    if cost >= 1:
        return f"${cost:.2f}"
    if cost >= 0.01:
        return f"${cost:.3f}"
    return f"${cost:.4f}"


def _path_name(value: str) -> str:
    """Return a basename for paths recorded on either Unix or Windows."""
    return PureWindowsPath(value).name if "\\" in value else Path(value).name


# Per-1M-token USD pricing (input, output), sourced from the Claude API model
# table. Cache writes bill at 1.25x input, cache reads at 0.10x input.
_MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-fable-5": (10.0, 50.0),
    "claude-mythos-5": (10.0, 50.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-opus-4-7": (5.0, 25.0),
    "claude-opus-4-6": (5.0, 25.0),
    "claude-opus-4-5": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


def _model_pricing(model: str) -> tuple[float, float] | None:
    if not model:
        return None
    m = model.lower()
    for key, price in _MODEL_PRICING.items():
        if key in m:
            return price
    if "fable" in m or "mythos" in m:
        return (10.0, 50.0)
    if "haiku" in m:
        return (1.0, 5.0)
    if "sonnet" in m:
        return (3.0, 15.0)
    if "opus" in m:
        return (5.0, 25.0)
    return None


def _cost_for(model: str, usage: dict[str, Any]) -> float | None:
    price = _model_pricing(model)
    if price is None:
        return None
    price_in, price_out = price
    return (
        usage.get("input", 0) * price_in
        + usage.get("cache_write", 0) * price_in * 1.25
        + usage.get("cache_read", 0) * price_in * 0.10
        + usage.get("output", 0) * price_out
    ) / 1_000_000


def _blank_totals() -> dict[str, Any]:
    return {
        "input": 0,
        "output": 0,
        "cache_read": 0,
        "cache_write": 0,
        "cost": 0.0,
        "cost_available": False,
        "has_tokens": False,
    }


def _add_usage(totals: dict[str, Any], usage: dict[str, Any]) -> None:
    for key in ("input", "output", "cache_read", "cache_write"):
        totals[key] += usage.get(key, 0)
    totals["has_tokens"] = True
    cost = usage.get("cost")
    if cost is not None:
        totals["cost"] += cost
        totals["cost_available"] = True


# --------------------------------------------------------------------------
# Semantic session scanning
# --------------------------------------------------------------------------


@dataclass
class SessionSummary:
    path: Path
    session_id: str
    size: int
    started: datetime | None = None
    last_activity: datetime | None = None
    events: int = 0
    tool_calls: int = 0
    executes: int = 0
    errors: int = 0
    stopped: bool = False
    pid: int | None = None
    nexus_id: str | None = None
    agent: str | None = None
    targets: list[dict[str, Any]] = field(default_factory=list)
    agent_sessions: dict[str, str] = field(default_factory=dict)
    agent_session_refs: set[tuple[str, str]] = field(default_factory=set)

    @property
    def status(self) -> str:
        if self.stopped:
            return "closed"
        if self.pid is not None and _pid_alive(self.pid):
            return "running"
        return "killed"

    @property
    def has_analysis_activity(self) -> bool:
        """Whether this trace represents a user-visible analysis session."""
        return self.tool_calls > 0 or bool(
            self.agent_session_refs or self.agent_sessions
        )

    @property
    def display_target(self) -> str:
        names = []
        for target in self.targets:
            path = target.get("idb_path") or target.get("exe_path")
            if isinstance(path, str) and path:
                names.append(_path_name(path))
        unique = list(dict.fromkeys(names))
        if not unique:
            return "No database opened"
        if len(unique) == 1:
            return unique[0]
        return f"{unique[0]} +{len(unique) - 1}"


def _summary_agent_sessions(summary: SessionSummary) -> set[tuple[str, str]]:
    if summary.agent_session_refs:
        return summary.agent_session_refs
    return set(summary.agent_sessions.items())


def _windows_pid_alive(pid: int) -> bool:
    """Check a PID without using ``os.kill(pid, 0)`` on Windows.

    On Windows, signal 0 is ``CTRL_C_EVENT`` rather than a harmless existence
    probe.  Calling ``os.kill(pid, 0)`` can therefore interrupt the process (or
    the dashboard itself) and has also been observed to raise ``SystemError``.
    """

    if os.name != "nt":
        raise RuntimeError("This function is only supported on Windows.")

    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    error_access_denied = 5
    still_active = 259

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    get_exit_code.restype = wintypes.BOOL

    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        # Protected system processes may deny access, which still proves that
        # the PID exists.
        return ctypes.get_last_error() == error_access_denied
    try:
        exit_code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == still_active
    finally:
        close_handle(handle)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError, SystemError):
        return False
    return True


def _record_session_fields(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("session")
    return value if isinstance(value, dict) else {}


def _targets_match(left: dict[str, Any], right: dict[str, Any]) -> bool:
    for key in ("instance_id", "record_id", "idb_path"):
        left_value = left.get(key)
        right_value = right.get(key)
        if left_value and right_value and left_value == right_value:
            return True
    return False


def _add_target(summary: SessionSummary, value: object) -> None:
    if not isinstance(value, dict):
        return
    nested = value.get("database")
    raw_target = nested if isinstance(nested, dict) else value
    target: dict[str, Any] = {str(key): item for key, item in raw_target.items()}
    if not any(target.get(key) for key in ("record_id", "instance_id", "idb_path")):
        return
    for index, existing in enumerate(summary.targets):
        if _targets_match(existing, target):
            summary.targets[index] = {**existing, **target}
            return
    summary.targets.append(dict(target))


def _resolve_agent_session_path(recorded: str, trace_path: Path) -> str:
    if ARCHIVE_PATH is not None:
        contextual = ARCHIVE_SESSION_AGENT_PATHS.get(
            (str(trace_path.resolve()), recorded)
        )
        if contextual is not None:
            return contextual
        # Keep unresolved references visible, but never use the receiving
        # machine's filesystem for paths that were not included in the ZIP.
        return recorded
    if Path(recorded).is_file():
        return recorded
    resolved_root = SESSIONS_DIR.resolve()
    for ancestor in (trace_path.parent, trace_path.parent.parent):
        candidate = ancestor / "session.jsonl"
        if (
            candidate.is_file()
            and candidate.resolve().is_relative_to(resolved_root)
            and candidate != trace_path
        ):
            return str(candidate)
    return recorded


def _summarize_session(
    path: Path, *, agent_transcript: Path | None = None
) -> SessionSummary:
    summary = SessionSummary(path, path.stem, path.stat().st_size)
    records = _read_jsonl(path)
    summary.events = len(records)
    for record in records:
        ts = _parse_ts(record.get("ts"))
        if ts is not None:
            if summary.started is None:
                summary.started = ts
            summary.last_activity = ts
        if isinstance(record.get("pid"), int):
            summary.pid = record["pid"]
        server_id = record.get("mcp_server_id")
        if isinstance(server_id, str) and server_id:
            summary.session_id = server_id

        session = _record_session_fields(record)
        nexus_id = session.get("nexus_id")
        if isinstance(nexus_id, str) and nexus_id:
            summary.nexus_id = nexus_id
        for kind, session_path in iter_agent_session_paths(session):
            if agent_transcript is not None:
                session_path = str(agent_transcript)
            else:
                session_path = _resolve_agent_session_path(session_path, path)
            summary.agent_sessions[kind] = session_path
            summary.agent_session_refs.add((kind, session_path))

        event = record.get("event")
        if event == "mcp_started":
            agent = record.get("agent")
            if isinstance(agent, str) and agent:
                summary.agent = agent
        if event == "tool_call":
            summary.tool_calls += 1
            if record.get("tool") == "execute_python":
                summary.executes += 1
        elif event == "tool_error":
            summary.errors += 1
        elif event == "mcp_stopped":
            summary.stopped = True
        if event in {"database_opened", "database_reused", "database_disconnected"}:
            _add_target(summary, record.get("target"))
        if event == "tool_result":
            _add_target(summary, record.get("output"))
    return summary


def _is_session_jsonl(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
            if not first_line:
                return False
            record = json.loads(first_line)
            return isinstance(record, dict) and record.get("schema") == 1
    except (OSError, json.JSONDecodeError):
        return False


def _session_route_name(path: Path) -> str:
    try:
        return str(path.relative_to(SESSIONS_DIR))
    except ValueError:
        return path.name


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _is_benchmark_dir(directory: Path) -> bool:
    for child in directory.iterdir():
        if child.is_dir() and _UUID_RE.match(child.name):
            return (child / "result.json").is_file()
    return False


def _scan_benchmark_runs(directory: Path) -> list[SessionSummary]:
    summaries: list[SessionSummary] = []
    for run_dir in sorted(directory.iterdir()):
        if not run_dir.is_dir() or not _UUID_RE.match(run_dir.name):
            continue
        mcp_trace = run_dir / "logs" / "ida-nexus" / "session.jsonl"
        if not mcp_trace.is_file() or not _is_session_jsonl(mcp_trace):
            continue
        agent_transcript = run_dir / "logs" / "session.jsonl"
        summary = _summarize_session(
            mcp_trace,
            agent_transcript=agent_transcript if agent_transcript.is_file() else None,
        )
        if summary.has_analysis_activity:
            summaries.append(summary)
    return summaries


def _scan_sessions() -> list[SessionSummary]:
    if not SESSIONS_DIR.is_dir():
        return []
    if _is_benchmark_dir(SESSIONS_DIR):
        summaries = _scan_benchmark_runs(SESSIONS_DIR)
    else:
        summaries = [
            summary
            for path in sorted(SESSIONS_DIR.glob("*.jsonl"))
            if _is_session_jsonl(path)
            and (summary := _summarize_session(path)).has_analysis_activity
        ]
    summaries.sort(key=lambda item: item.started or _MIN_DT, reverse=True)
    return summaries


def _known_agent_sessions() -> dict[str, list[SessionSummary]]:
    """Map referenced transcripts to sessions and provide the HTTP allowlist."""
    mapping: dict[str, list[SessionSummary]] = {}
    for summary in _scan_sessions():
        for _kind, session_path in _summary_agent_sessions(summary):
            mapping.setdefault(session_path, []).append(summary)
    return mapping


# --------------------------------------------------------------------------
# HTML rendering primitives
# --------------------------------------------------------------------------

_PAGE_CSS = """
:root {
  --bg: #f6f7f9; --panel: #ffffff; --border: #dde1e6; --text: #1b1f24;
  --muted: #59636e; --accent: #0969da; --user: #ddf4ff; --assistant: #ffffff;
  --code-bg: #f0f2f5; --error: #cf222e; --ok: #1a7f37;
  --kw: #cf222e; --str: #0a3069; --num: #953800; --com: #59636e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8d96a0; --accent: #4493f8; --user: #121d2f; --assistant: #161b22;
    --code-bg: #0d1117; --error: #f85149; --ok: #3fb950;
    --kw: #ff7b72; --str: #a5d6ff; --num: #ffa657; --com: #8d96a0;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 24px 16px 64px; }
header.top {
  background: var(--panel); border-bottom: 1px solid var(--border);
  padding: 12px 16px; display: flex; align-items: baseline; gap: 16px;
}
header.top h1 { font-size: 16px; margin: 0; }
header.top .sub { color: var(--muted); font-size: 12px; }
h2 { font-size: 18px; margin: 24px 0 12px; }
table.sessions { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
table.sessions th, table.sessions td {
  padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border);
  vertical-align: top; }
table.sessions th { font-size: 12px; color: var(--muted); font-weight: 600;
  background: var(--bg); cursor: pointer; user-select: none;
  white-space: nowrap; }
table.sessions th:hover { color: var(--text); }
table.sessions th::after { content: ""; opacity: 0.6; font-size: 10px; }
table.sessions th.sort-asc::after { content: " \\2191"; }
table.sessions th.sort-desc::after { content: " \\2193"; }
table.sessions tr:last-child td { border-bottom: none; }
table.sessions td.date { white-space: nowrap; }
table.sessions td.model { white-space: nowrap; }
table.sessions td.model > div + div { margin-top: 2px; }
table.sessions th:first-child, table.sessions td:first-child {
  max-width: 320px; width: 320px; }
table.sessions td:first-child a { word-break: break-all; }
.table-scroll { overflow-x: auto; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-size: 11px; font-weight: 600; border: 1px solid var(--border); }
.badge.claude { color: #b0530a; border-color: #b0530a55; }
.badge.codex { color: var(--ok); border-color: var(--ok); }
.badge.pi { color: var(--accent); border-color: var(--accent); }
.badge.omp { color: #9b59ff; border-color: #9b59ff; }
.badge.open { color: var(--ok); border-color: var(--ok); }
.badge.closed { color: var(--muted); }
.badge.killed { color: var(--error); border-color: var(--error); opacity: 0.75; }
.badge.error { color: var(--error); border-color: var(--error); }
.badge.internal { color: var(--muted); border-style: dashed; }
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px; }
.card { background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; margin: 12px 0; overflow: hidden; }
.card > .head { padding: 8px 12px; display: flex; gap: 10px; align-items: baseline;
  flex-wrap: wrap; border-bottom: 1px solid var(--border); background: var(--bg); }
.card > .head .title { font-weight: 600; }
.card > .head .ts { color: var(--muted); font-size: 12px; margin-left: auto; }
.card > .body { padding: 12px; }
.response-label { display: flex; gap: 8px; align-items: baseline; margin: 10px 0 4px;
  color: var(--muted); font-size: 12px; }
.response-label:first-child { margin-top: 0; }
.execution-field { margin-top: 10px; }
.execution-field > .name { color: var(--muted); font-weight: 600; margin-bottom: 2px; }
.execution-field > .empty { color: var(--muted); font-style: italic; padding: 4px 0; }
pre { background: var(--code-bg); border: 1px solid var(--border);
  border-radius: 6px; padding: 10px 12px; overflow-x: auto; margin: 8px 0;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px; line-height: 1.45; white-space: pre; }
code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px; background: var(--code-bg); padding: 1px 4px;
  border-radius: 4px; }
pre code { background: none; padding: 0; }
.kw { color: var(--kw); } .str { color: var(--str); }
.num { color: var(--num); } .com { color: var(--com); font-style: italic; }
details { margin: 8px 0; }
details > summary { cursor: pointer; color: var(--muted); font-size: 12px;
  user-select: none; }
details[open] > summary { margin-bottom: 4px; }
.msg { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px;
  margin: 12px 0; background: var(--assistant); }
.msg.user { background: var(--user); }
.msg .who { font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--muted); margin-bottom: 4px;
  display: flex; gap: 8px; align-items: baseline; }
.msg .who .ts { font-weight: 400; text-transform: none; letter-spacing: 0;
  margin-left: auto; }
.msg .text { white-space: pre-wrap; word-break: break-word; }
.toolcall { border-left: 3px solid var(--accent); }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px;
  margin: 8px 0; font-size: 13px; }
.kv .k { color: var(--muted); }
.kv .v { word-break: break-all; }
.usage { margin-top: 6px; font-size: 11px; color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; }
.transcript-item { position: relative; padding-left: 16px; margin: 4px 0; }
.transcript-item::before { content: ""; position: absolute; left: 3px;
  top: 6px; bottom: 6px; width: 2px; background: var(--accent);
  opacity: 0.4; border-radius: 2px; }
.transcript-item .msg { margin: 6px 0; }
.transcript-item > details { margin: 6px 0; }
.unsupported-event { border-left: 3px dashed var(--border); padding: 6px 10px;
  background: var(--panel); border-radius: 4px; }
.unsupported-event > summary { color: var(--text); }
.unsupported-event > summary .ts { float: right; margin-left: 12px; }
body.hide-transcript .transcript-item { display: none; }
body.hide-unsupported .unsupported-event,
body.hide-unsupported .unsupported-transcript-item { display: none; }
.toolbar { display: flex; gap: 12px; margin: 12px 0; font-size: 13px;
  align-items: center; flex-wrap: wrap; }
.toolbar button { background: var(--panel); color: var(--text);
  border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px;
  cursor: pointer; font-size: 12px; }
.toolbar label { display: inline-flex; gap: 5px; align-items: center; cursor: pointer; }
.token-note { color: var(--muted); font-size: 12px; margin: -4px 0 12px; }
.empty { text-align: center; padding: 48px; color: var(--muted); }
.crumbs { font-size: 13px; margin-bottom: 8px; color: var(--muted); }
"""

_PAGE_JS = """
function setAllDetails(open) {
  document.querySelectorAll('details').forEach(function (d) { d.open = open; });
}
function setVisible(hiddenClass, visible) {
  document.body.classList.toggle(hiddenClass, !visible);
}
function sortTable(table, col, th) {
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var dir = th.getAttribute('data-dir') === 'asc' ? 'desc' : 'asc';
  var headers = th.parentNode.children;
  for (var i = 0; i < headers.length; i++) {
    headers[i].removeAttribute('data-dir');
    headers[i].classList.remove('sort-asc', 'sort-desc');
  }
  th.setAttribute('data-dir', dir);
  th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
  var mult = dir === 'asc' ? 1 : -1;
  function key(row) {
    var cell = row.cells[col];
    var v = cell.getAttribute('data-sort');
    return v === null ? cell.textContent.trim() : v;
  }
  rows.sort(function (a, b) {
    var x = key(a), y = key(b);
    if (x === '' && y === '') return 0;
    if (x === '') return 1;   // blanks always sort last
    if (y === '') return -1;
    var nx = Number(x), ny = Number(y);
    if (Number.isFinite(nx) && Number.isFinite(ny)) return (nx - ny) * mult;
    return x.localeCompare(y) * mult;
  });
  rows.forEach(function (r) { tbody.appendChild(r); });
}
function initSort() {
  document.querySelectorAll('table.sessions thead th').forEach(function (th, i) {
    th.addEventListener('click', function () {
      sortTable(th.closest('table'), i, th);
    });
  });
}
document.addEventListener('DOMContentLoaded', initSort);
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _source_label() -> str:
    return str(ARCHIVE_PATH or SESSIONS_DIR)


def _page(title: str, body: str, subtitle: str = "", standalone: bool = False) -> str:
    heading = "ida-nexus dashboard"
    heading_html = (
        f"<h1>{_e(heading)}</h1>"
        if standalone
        else f'<h1><a href="/">{_e(heading)}</a></h1>'
    )
    sub = subtitle if (subtitle or standalone) else _source_label()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>{_PAGE_CSS}</style>
<script>{_PAGE_JS}</script>
</head>
<body>
<header class="top">
  {heading_html}
  <span class="sub">{_e(sub)}</span>
</header>
<div class="wrap">
{body}
</div>
</body>
</html>"""


_PY_KEYWORDS = (
    "False|None|True|and|as|assert|async|await|break|class|continue|def|del|"
    "elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|"
    "not|or|pass|raise|return|try|while|with|yield|self"
)

_PY_TOKEN_RE = re.compile(
    r"(?P<comment>#[^\n]*)"
    r'|(?P<string>[rbufRBUF]{0,2}("""(?:[^"\\]|\\.|"(?!""))*"""'
    r"|'''(?:[^'\\]|\\.|'(?!''))*'''"
    r'|"(?:[^"\\\n]|\\.)*"'
    r"|'(?:[^'\\\n]|\\.)*'))"
    r"|(?P<number>\b(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+"
    r"|\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?)\b)"
    rf"|(?P<keyword>\b(?:{_PY_KEYWORDS})\b)"
)

_TOKEN_CLASSES = {"comment": "com", "string": "str", "number": "num", "keyword": "kw"}


def _highlight_python(code: str) -> str:
    parts: list[str] = []
    pos = 0
    for match in _PY_TOKEN_RE.finditer(code):
        parts.append(_e(code[pos : match.start()]))
        css = _TOKEN_CLASSES[match.lastgroup or "keyword"]
        parts.append(f'<span class="{css}">{_e(match.group())}</span>')
        pos = match.end()
    parts.append(_e(code[pos:]))
    return "".join(parts)


def _python_block(code: str) -> str:
    return f"<pre><code>{_highlight_python(code.strip())}</code></pre>"


def _json_block(value: object, collapsed_label: str | None = None) -> str:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    block = f"<pre><code>{_e(text)}</code></pre>"
    if collapsed_label is None:
        return block
    return (
        f"<details><summary>{_e(collapsed_label)} "
        f"({len(text):,} chars)</summary>{block}</details>"
    )


def _model_json_block(value: object, collapsed_label: str) -> str:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    if len(text) <= 1500:
        return f"<pre><code>{_e(text)}</code></pre>"
    return (
        f"<details><summary>{_e(collapsed_label)} "
        f"({len(text):,} chars)</summary><pre><code>{_e(text)}</code></pre></details>"
    )


def _text_block(text: str, collapse_over: int = 1500, label: str = "output") -> str:
    block = f"<pre>{_e(text)}</pre>"
    if len(text) <= collapse_over:
        return block
    return (
        f"<details><summary>{_e(label)} ({len(text):,} chars)</summary>"
        f"{block}</details>"
    )


_FENCE_RE = re.compile(r"^```([\w+-]*)\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_BOLD_RE = re.compile(r"\*\*([^*\n]+)\*\*")


def _render_markdownish(text: str) -> str:
    """Minimal markdown: fenced code blocks, inline code, and bold."""

    def render_span(span: str) -> str:
        escaped = _e(span)
        escaped = _INLINE_CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
        escaped = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)
        return escaped

    parts: list[str] = []
    pos = 0
    for match in _FENCE_RE.finditer(text):
        parts.append(render_span(text[pos : match.start()]))
        lang, code = match.group(1), match.group(2)
        if lang in ("python", "py"):
            parts.append(_python_block(code))
        else:
            parts.append(f"<pre>{_e(code)}</pre>")
        pos = match.end()
    parts.append(render_span(text[pos:]))
    return f'<div class="text">{"".join(parts)}</div>'


def _agent_link(kind: str, session_path: str, *, link: bool = True) -> str:
    if not link:
        return f'<span class="badge {kind}">{_e(kind)}</span>'
    href = f"/agent?path={quote(session_path)}"
    return f'<a class="badge {kind}" href="{_e(href)}">{_e(kind)}</a>'


_STATUS_CSS = {"running": "open", "closed": "closed", "killed": "killed"}


def _status_badge_value(status: str) -> str:
    css = _STATUS_CSS.get(status, "closed")
    return f'<span class="badge {css}">{_e(status)}</span>'


def _status_badge(summary: SessionSummary) -> str:
    return _status_badge_value(summary.status)


# --------------------------------------------------------------------------
# Index page
# --------------------------------------------------------------------------


def _session_model_names(summary: SessionSummary) -> list[str]:
    models: list[str] = []
    for _kind, session_path in sorted(_summary_agent_sessions(summary)):
        _items, meta, _detected_kind, _totals = _load_agent_items(session_path)
        model = meta.get("model")
        if model and model not in models:
            models.append(model)
    return models


def _cost_cell(totals: dict[str, Any]) -> tuple[str, str]:
    if totals["cost_available"]:
        return _format_cost(totals["cost"]), f"{totals['cost']:.6f}"
    if totals["has_tokens"]:
        return '<span class="muted" title="pricing unavailable">n/a</span>', ""
    return '<span class="muted">—</span>', ""


def _summary_index_row(summary: SessionSummary) -> str:
    errors = (
        f'<span class="badge error">{summary.errors} err</span>'
        if summary.errors
        else ""
    )
    cost, cost_sort = _cost_cell(_session_usage(summary))
    started_sort = f"{summary.started.timestamp():.6f}" if summary.started else ""
    activity_sort = (
        f"{summary.last_activity.timestamp():.6f}" if summary.last_activity else ""
    )
    href = f"/session/{quote(_session_route_name(summary.path))}"
    model_names = _session_model_names(summary)
    models = ", ".join(model_names)
    model_cell = (
        "".join(f"<div>{_e(name)}</div>" for name in model_names)
        if model_names
        else "—"
    )
    agents = " ".join(
        _agent_link(kind, path)
        for kind, path in sorted(_summary_agent_sessions(summary))
    )
    return (
        "<tr>"
        f'<td data-sort="{_e(summary.display_target.lower())}">'
        f'<a href="{_e(href)}"><strong>{_e(summary.display_target)}</strong></a>'
        f'<div class="mono muted">{_e(summary.session_id)}</div>{agents}</td>'
        f'<td class="mono model" data-sort="{_e(models.lower())}">'
        f"{model_cell}</td>"
        f'<td class="date" data-sort="{_e(started_sort)}">{_e(_format_ts(summary.started))}</td>'
        f'<td class="date" data-sort="{_e(activity_sort)}">{_e(_format_ts(summary.last_activity))}</td>'
        f'<td data-sort="{_e(summary.status)}">{_status_badge(summary)} {errors}</td>'
        f'<td class="mono" data-sort="{_e(cost_sort)}">{cost}</td>'
        "</tr>"
    )


def render_index() -> str:
    summaries = _scan_sessions()
    if not summaries:
        return _page(
            "ida-nexus dashboard",
            '<div class="empty">No sessions found in '
            f"<code>{_e(_source_label())}</code>.<br>"
            "Open a database through the MCP server first.</div>",
        )
    rows = "".join(_summary_index_row(summary) for summary in summaries)
    body = f"""
<h2>Analysis sessions <span class="muted">({len(summaries)})</span></h2>
<div class="table-scroll">
<table class="sessions">
<thead><tr>
  <th>Targets / session</th><th>Model</th>
  <th class="sort-desc" data-dir="desc">Started</th>
  <th>Last activity</th><th>Status</th><th>Cost</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<p class="muted" style="font-size:12px;margin-top:8px">Click a column header to sort.</p>
"""
    return _page("ida-nexus dashboard", body)


# --------------------------------------------------------------------------
# Session timeline page
# --------------------------------------------------------------------------


def _card(title: str, ts: datetime | None, body: str, extra_head: str = "") -> str:
    ts_html = f'<span class="ts">{_e(_format_ts(ts))}</span>' if ts else ""
    body_html = f'<div class="body">{body}</div>' if body else ""
    return (
        f'<div class="card"><div class="head">'
        f'<span class="title">{title}</span>{extra_head}{ts_html}</div>'
        f"{body_html}</div>"
    )


def _call_id_badge(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    display = value if len(value) <= 12 else f"{value[:8]}…"
    escaped = _e(value)
    return (
        f'<span class="badge mono" data-call-id="{escaped}" '
        f'title="call_id: {escaped}">call {_e(display)}</span>'
    )


def _response_label(kind: str, text: str) -> str:
    css = "internal" if kind == "internal" else "open"
    return (
        f'<div class="response-label"><span class="badge {css}">{_e(kind)}</span>'
        f"{_e(text)}</div>"
    )


def _model_facing_error_payload(error: object) -> dict[str, Any]:
    if not isinstance(error, dict):
        message = str(error) or "Unknown error"
    else:
        message = str(error.get("message") or "Unknown error")
        if error.get("type") == "RemoteError":
            details = error.get("details")
            if isinstance(details, dict):
                sections = [message]
                for label in ("stdout", "stderr", "traceback"):
                    value = details.get(label)
                    if isinstance(value, str) and value:
                        sections.append(f"{label}:\n{value.rstrip()}")
                message = "\n\n".join(sections)
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def _python_execution_result_html(output: object) -> str:
    if not isinstance(output, dict):
        return _model_json_block(output, "PythonExecutionResult returned to model")

    parts: list[str] = []
    for name in ("result", "stdout", "stderr"):
        value = output.get(name)
        if name in {"stdout", "stderr"} and (name not in output or value == ""):
            continue
        parts.append(
            f'<div class="execution-field"><div class="name mono">{name}</div>'
        )
        if name not in output:
            parts.append('<div class="empty">missing</div>')
        elif isinstance(value, str):
            if value:
                parts.append(
                    _text_block(
                        value,
                        label=f"{name} returned by MCP",
                    )
                )
            else:
                parts.append('<div class="empty">empty string</div>')
        else:
            parts.append(_model_json_block(value, f"{name} returned by MCP"))
        parts.append("</div>")
    return "".join(parts)


def _render_tool_call_card(call: dict[str, Any], *, pending: bool) -> str:
    tool = str(call.get("tool", "?"))
    raw_arguments = call.get("input")
    arguments: dict[str, Any] = (
        {str(key): value for key, value in raw_arguments.items()}
        if isinstance(raw_arguments, dict)
        else {}
    )
    parts: list[str] = []
    if tool == "execute_python" and isinstance(arguments.get("code"), str):
        parts.append(_python_block(arguments["code"]))
        rest = {key: value for key, value in arguments.items() if key != "code"}
        if rest:
            parts.append(_json_block(rest, collapsed_label="arguments"))
    elif (
        tool == "reference"
        and isinstance(arguments.get("query"), str)
        and set(arguments) == {"query"}
    ):
        parts.append(
            '<div class="execution-field"><div class="name mono">query</div>'
            f'<div class="text">{_e(arguments["query"])}</div></div>'
        )
    else:
        parts.append(_json_block(arguments, collapsed_label="arguments"))

    state = "pending" if pending else "started"
    badge = f'<span class="badge muted">{state}</span>'
    call_ts = _parse_ts(call.get("ts"))
    return _card(
        f"{_e(tool)} {badge}",
        call_ts,
        "".join(parts),
        _call_id_badge(call.get("call_id")),
    )


def _render_tool_response_card(
    response: dict[str, Any], call: dict[str, Any] | None
) -> str:
    tool = str(response.get("tool") or (call or {}).get("tool") or "?")
    response_ts = _parse_ts(response.get("ts"))
    call_ts = _parse_ts((call or {}).get("ts"))
    duration = ""
    if isinstance(response.get("duration_ms"), (int, float)):
        duration = _format_duration(float(response["duration_ms"]) / 1000)
    elif call_ts and response_ts:
        duration = _format_duration((response_ts - call_ts).total_seconds())
    duration_html = f'<span class="muted">{_e(duration)}</span>' if duration else ""
    call_id = response.get("call_id") or (call or {}).get("call_id")
    extra_head = _call_id_badge(call_id) + duration_html

    parts: list[str] = []
    if response.get("event") == "tool_result":
        badge = '<span class="badge open">ok</span>'
        output = response.get("output")
        if tool == "execute_python":
            parts.append(
                _response_label(
                    "MCP result",
                    "PythonExecutionResult fields; agent clients may truncate before model ingestion",
                )
            )
            parts.append(_python_execution_result_html(output))
        elif tool == "reference" and isinstance(output, str):
            parts.append(_response_label("model-facing", "text tool result"))
            parts.append(_text_block(output, 800, "reference result"))
        elif output is not None:
            parts.append(_response_label("model-facing", "structured tool result"))
            parts.append(_model_json_block(output, "tool result returned to model"))
    else:
        badge = '<span class="badge error">error</span>'
        error = response.get("error")
        parts.append(
            _response_label(
                "model-facing",
                "MCP error JSON; no PythonExecutionResult was returned",
            )
        )
        parts.append(
            _model_json_block(
                _model_facing_error_payload(error),
                "MCP error returned to model",
            )
        )
        parts.append(_response_label("internal", "server diagnostic metadata"))
        parts.append(_json_block(error, collapsed_label="internal error diagnostic"))

    return _card(f"{_e(tool)} {badge}", response_ts, "".join(parts), extra_head)


_LIFECYCLE_EVENTS = {
    "mcp_started",
    "mcp_initialized",
    "mcp_stopped",
    "database_opened",
    "database_reused",
    "database_disconnected",
    "database_saved",
    "database_released",
    "database_release_error",
    "plugin_install_started",
    "plugin_install_succeeded",
    "plugin_install_failed",
}


def _render_event_card(
    event: str,
    record: dict[str, Any],
    ts: datetime | None,
    call_id: str | None = None,
) -> str:
    linked_call_id = record.get("call_id") or call_id
    details = {
        key: value
        for key, value in record.items()
        if key not in {"schema", "ts", "event", "session", "mcp_server_id", "call_id"}
    }
    return _card(
        _e(event),
        ts,
        _json_block(details) if details else "",
        _call_id_badge(linked_call_id),
    )


def _enclosing_call_id(
    ts: datetime | None,
    calls: dict[str, dict[str, Any]],
    responses: dict[str, dict[str, Any]],
) -> str | None:
    if ts is None:
        return None
    candidates: list[str] = []
    for call_id, call in calls.items():
        response = responses.get(call_id)
        if response is None:
            continue
        call_ts = _parse_ts(call.get("ts"))
        response_ts = _parse_ts(response.get("ts"))
        if (
            call_ts is not None
            and response_ts is not None
            and call_ts <= ts <= response_ts
        ):
            candidates.append(call_id)
    return candidates[0] if len(candidates) == 1 else None


def _add_session_timeline(
    records: list[dict[str, Any]],
    add_event: Callable[[datetime | None, str], None],
) -> None:
    calls = {
        record["call_id"]: record
        for record in records
        if record.get("event") == "tool_call" and isinstance(record.get("call_id"), str)
    }
    responses = {
        record["call_id"]: record
        for record in records
        if record.get("event") in {"tool_result", "tool_error"}
        and isinstance(record.get("call_id"), str)
    }
    completed_call_ids = set(responses)

    for record in records:
        event = record.get("event")
        ts = _parse_ts(record.get("ts"))
        if event == "tool_call":
            call_id = record.get("call_id")
            add_event(
                ts,
                _render_tool_call_card(
                    record,
                    pending=not (
                        isinstance(call_id, str) and call_id in completed_call_ids
                    ),
                ),
            )
        elif event in {"tool_result", "tool_error"}:
            call_id = record.get("call_id")
            call = calls.get(call_id) if isinstance(call_id, str) else None
            add_event(ts, _render_tool_response_card(record, call))
        elif event in _LIFECYCLE_EVENTS:
            linked_call_id = _enclosing_call_id(ts, calls, responses)
            add_event(
                ts,
                _render_event_card(str(event), record, ts, linked_call_id),
            )
        elif event is not None:
            # Catch-all so an event type we don't explicitly know about yet
            # still shows up on the timeline instead of being silently dropped.
            add_event(ts, _render_event_card(str(event), record, ts))


def _transcript_window(
    summary: SessionSummary, session_path_key: Path, session_path: str
) -> tuple[datetime | None, datetime | None]:
    """Time bounds attributing transcript items to this semantic session.

    A single agent transcript may span several semantic sessions. Messages from
    the moment the previous instance ended up to the moment the next instance
    started belong to this one, so the wrap-up after a close and the prompt
    before an open are both captured.
    """
    siblings = _known_agent_sessions().get(session_path, [])
    ordered = sorted(siblings, key=lambda s: s.started or _MIN_DT)
    lower: datetime | None = None
    upper: datetime | None = None
    for index, sibling in enumerate(ordered):
        if sibling.path != session_path_key:
            continue
        if index > 0:
            lower = ordered[index - 1].last_activity
        if index < len(ordered) - 1:
            upper = ordered[index + 1].started
        break
    return lower, upper


def _in_window(
    ts: datetime | None, lower: datetime | None, upper: datetime | None
) -> bool:
    if ts is None:
        return False
    if lower is not None and ts <= lower:
        return False
    return not (upper is not None and ts >= upper)


def _interleave_transcript(
    summary: SessionSummary,
    add_event: Callable[[datetime | None, str], None],
) -> tuple[int, int]:
    """Add linked-transcript conversation items to the timeline, in time order.

    IDA calls are skipped because they already appear as session events. Other
    agent tool calls remain visible so the inline transcript is complete.
    Returns total and unsupported-event counts.
    """
    added = 0
    unsupported = 0
    for _kind, session_path in _summary_agent_sessions(summary):
        lower, upper = _transcript_window(summary, summary.path, session_path)
        items, _meta, _kind, _totals = _load_agent_items(session_path)
        for item in items:
            if (
                item.category == "tool"
                and item.tool_name is not None
                and _nexus_tool_name(item.tool_name) is not None
            ) or not _in_window(item.ts, lower, upper):
                continue
            unsupported_class = (
                " unsupported-transcript-item" if item.category == "event" else ""
            )
            add_event(
                item.ts,
                f'<div class="transcript-item{unsupported_class}">{item.html}</div>',
            )
            added += 1
            unsupported += item.category == "event"
    return added, unsupported


def _session_usage(summary: SessionSummary) -> dict[str, Any]:
    """Token/cost totals for one semantic session, scoped to its time window.

    Claude and Pi usage is summed per-message within the window. Codex has only
    whole-session cumulative counts (no per-message data, no cost), so those are
    used as-is when the instance has no windowable per-message usage.
    """
    totals = _blank_totals()
    for _kind, session_path in _summary_agent_sessions(summary):
        lower, upper = _transcript_window(summary, summary.path, session_path)
        items, _meta, kind, session_totals = _load_agent_items(session_path)
        windowed = [
            it.usage for it in items if it.usage and _in_window(it.ts, lower, upper)
        ]
        if windowed:
            for usage in windowed:
                _add_usage(totals, usage)
        elif kind == "codex" and session_totals["has_tokens"]:
            _add_usage(totals, session_totals)
    return totals


def _totals_summary_html(totals: dict[str, Any]) -> str:
    parts = [
        f"in {_format_tokens(totals['input'])}",
        f"out {_format_tokens(totals['output'])}",
        f"cache read {_format_tokens(totals['cache_read'])}",
        f"cache write {_format_tokens(totals['cache_write'])}",
    ]
    if totals["cost_available"]:
        parts.append(_format_cost(totals["cost"]))
    else:
        parts.append("cost n/a")
    return " · ".join(_e(p) for p in parts)


def render_session(name: str, *, export: bool = False) -> str | None:
    """Render one semantic MCP session, optionally as self-contained HTML."""
    if "\\" in name or not name.endswith(".jsonl"):
        return None
    sessions_dir = SESSIONS_DIR.resolve()
    path = (sessions_dir / name).resolve()
    if not path.is_relative_to(sessions_dir) or not path.is_file():
        return None
    summary = _summarize_session(path)
    records = _read_jsonl(path)

    events: list[tuple[datetime, int, str]] = []
    sequence = 0

    def add_event(ts: datetime | None, event_html: str) -> None:
        nonlocal sequence
        events.append((ts or _MIN_DT, sequence, event_html))
        sequence += 1

    _add_session_timeline(records, add_event)
    transcript_count, unsupported_count = _interleave_transcript(summary, add_event)
    events.sort(key=lambda item: (item[0], item[1]))

    agents = " ".join(
        _agent_link(kind, session_path, link=not export)
        for kind, session_path in sorted(_summary_agent_sessions(summary))
    )
    targets = (
        "<br>".join(
            f'<span class="mono">{_e(str(target.get("idb_path") or target.get("exe_path") or "?"))}</span> '
            f'<span class="badge">{_e(str(target.get("backend") or "unknown"))}</span>'
            for target in summary.targets
        )
        or '<span class="muted">none recorded</span>'
    )
    totals = _session_usage(summary)
    models = ", ".join(_session_model_names(summary))
    meta_rows = [
        ("Session", f'<span class="mono">{_e(summary.session_id)}</span>'),
        ("Targets", targets),
        (
            "Duration",
            _e(
                _format_duration(
                    (summary.last_activity - summary.started).total_seconds()
                )
            )
            if summary.started and summary.last_activity
            else "?",
        ),
        ("Agent session", agents or '<span class="muted">none recorded</span>'),
    ]
    if summary.agent:
        meta_rows.append(("Agent", _e(summary.agent)))
    if models:
        meta_rows.append(("Model", _e(models)))
    if summary.nexus_id:
        meta_rows.append(
            ("Nexus ID", f'<span class="mono">{_e(summary.nexus_id)}</span>')
        )
    if totals["has_tokens"]:
        meta_rows.append(("Tokens", _totals_summary_html(totals)))
    if not export:
        trace_path = ARCHIVE_SOURCE_PATHS.get(path.resolve(), str(path))
        meta_rows.insert(
            0, ("Trace file", f'<span class="mono">{_e(trace_path)}</span>')
        )
    kv = "".join(
        f'<span class="k">{key}</span><span class="v">{value}</span>'
        for key, value in meta_rows
    )
    controls = [
        '<button onclick="setAllDetails(true)">expand all</button>',
        '<button onclick="setAllDetails(false)">collapse all</button>',
    ]
    if transcript_count:
        controls.append(
            '<label><input type="checkbox" checked '
            "onchange=\"setVisible('hide-transcript', this.checked)\"> "
            f"transcript ({transcript_count})</label>"
        )
    if unsupported_count:
        controls.append(
            '<label><input type="checkbox" checked '
            "onchange=\"setVisible('hide-unsupported', this.checked)\"> "
            f"unsupported events ({unsupported_count})</label>"
        )
    if not export:
        controls.append(
            f'<a href="/export/session/{quote(name)}" style="align-self:center">export HTML</a>'
        )
    crumbs = (
        ""
        if export
        else f'<div class="crumbs"><a href="/">sessions</a> / {_e(name)}</div>'
    )
    token_note = (
        '<p class="token-note">Token usage reflects what the agent sent to the '
        "model; cached input is listed separately, and agent clients may truncate "
        "or save large MCP results before model ingestion.</p>"
        if totals["has_tokens"]
        else ""
    )
    body = f"""
{crumbs}
<h2>{_e(summary.display_target)} <span class="muted mono">{_e(summary.session_id)}</span> {_status_badge(summary)}</h2>
<div class="kv">{kv}</div>
<div class="toolbar">{"".join(controls)}</div>
{token_note}
{"".join(item[2] for item in events)}
"""
    return _page(
        f"{summary.display_target} — ida-nexus",
        body,
        subtitle=name,
        standalone=export,
    )


# --------------------------------------------------------------------------
# Agent transcript pages (Claude Code + Codex + Pi + OMP)
# --------------------------------------------------------------------------


def _detect_agent_kind(records: list[dict]) -> str:
    for record in records:
        record_type = record.get("type")
        if record_type == "session" and "version" in record:
            return "pi"
        if record_type in (
            "session_meta",
            "response_item",
            "turn_context",
            "event_msg",
        ):
            return "codex"
        if record_type in ("user", "assistant"):
            return "claude"
    return "unknown"


def _agent_models(records: list[dict], kind: str) -> list[str]:
    """Best-effort model names from Claude, Codex, and Pi transcripts."""
    if kind == "pi":
        records = _pi_active_branch_records(records)

    models: list[str] = []
    for record in records:
        record_type = record.get("type")
        model: object = None
        if kind == "claude" and record_type == "assistant":
            message = record.get("message")
            if isinstance(message, dict):
                model = message.get("model")
        elif kind == "pi":
            if record_type == "model_change":
                model = record.get("modelId")
            elif record_type == "message":
                message = record.get("message")
                if isinstance(message, dict) and message.get("role") == "assistant":
                    model = message.get("model")
        elif kind == "codex" and record_type in {"session_meta", "turn_context"}:
            payload = record.get("payload")
            if isinstance(payload, dict):
                model = payload.get("model")
                collaboration = payload.get("collaboration_mode")
                if model is None and isinstance(collaboration, dict):
                    settings = collaboration.get("settings")
                    if isinstance(settings, dict):
                        model = settings.get("model")
        if isinstance(model, str) and model and model not in models:
            models.append(model)
    return models


def _message_bubble(
    who: str, css: str, body: str, ts: datetime | None, tag: str = ""
) -> str:
    ts_html = f'<span class="ts">{_e(_format_ts(ts))}</span>' if ts else ""
    tag_html = f'<span class="badge">{_e(tag)}</span>' if tag else ""
    return (
        f'<div class="msg {css}"><div class="who">{_e(who)}{tag_html}{ts_html}</div>'
        f"{body}</div>"
    )


_NEXUS_TOOL_NAMES = {
    "search",
    "reference",
    "open_database",
    "execute_python",
    "list_databases",
    "save_database",
    "close_database",
}


def _nexus_tool_name(tool_name: str) -> str | None:
    """Return the underlying IDA tool name across Claude, Codex, and Pi forms."""
    if tool_name.startswith("ida_"):
        candidate = tool_name[4:]
    elif tool_name.startswith("mcp__"):
        candidate = tool_name.rsplit("__", 1)[-1]
    elif "." in tool_name:
        server, _, candidate = tool_name.rpartition(".")
        if "ida" not in server.lower():
            return None
    else:
        candidate = tool_name
    return candidate if candidate in _NEXUS_TOOL_NAMES else None


def _tool_display_name(tool_name: str) -> str:
    """Render names consistently, including Pi's ida_ prefixed tools."""
    nexus_name = _nexus_tool_name(tool_name)
    if tool_name.startswith("ida_") and nexus_name:
        return f"ida · {nexus_name}"
    if not tool_name.startswith("mcp__"):
        return tool_name
    parts = tool_name.split("__")
    if len(parts) < 3:
        return tool_name
    server = parts[1].rpartition("_")[2] or parts[1]
    return f"{server} · {parts[-1]}"


def _tool_input_html(tool_name: str, tool_input: object) -> str:
    """Render a tool invocation's input, special-casing code-mode calls."""
    if isinstance(tool_input, dict):
        tool_input = {k: v for k, v in tool_input.items() if k != "_meta"}
        code = tool_input.get("code")
        if _nexus_tool_name(tool_name) in (
            "execute_python",
            "search",
        ) and isinstance(code, str):
            rest = {k: v for k, v in tool_input.items() if k != "code"}
            parts = [_python_block(code)]
            if rest:
                parts.append(_json_block(rest, collapsed_label="other arguments"))
            return "".join(parts)
        command = tool_input.get("command")
        if tool_name == "Bash" and isinstance(command, str):
            return f"<pre>{_e(command)}</pre>"
    return _json_block(tool_input, collapsed_label="input")


def _tool_result_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(str(item.get("text", "")))
        return "\n".join(texts)
    if content is None:
        return ""
    return json.dumps(content, indent=2, ensure_ascii=False, default=str)


_SYSTEM_REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


def _claude_backgrounded_result(text: str) -> bool:
    return "moved to the background as task" in text.lower()


def _claude_truncated_result(text: str) -> bool:
    lowered = text.lower()
    return (
        "exceeds maximum allowed tokens" in lowered
        and "output has been saved to" in lowered
    )


@dataclass
class TranscriptItem:
    ts: datetime | None
    category: str  # user | assistant | thinking | tool | status | event
    html: str
    usage: dict[str, Any] | None = None  # attached once per source record
    tool_name: str | None = None


def _message_content_types_supported(
    content: object, supported: set[str], *, allow_text: bool = False
) -> bool:
    if isinstance(content, str):
        return allow_text
    if not isinstance(content, list):
        return False
    return all(
        isinstance(part, dict) and part.get("type") in supported for part in content
    )


def _claude_record_supported(record: dict[str, Any]) -> bool:
    record_type = record.get("type")
    message = record.get("message")
    if not isinstance(message, dict):
        return False
    content = message.get("content")
    if record_type == "user":
        return _message_content_types_supported(
            content, {"text", "tool_result"}, allow_text=True
        )
    if record_type == "assistant":
        return _message_content_types_supported(
            content, {"text", "thinking", "tool_use"}
        )
    return False


def _pi_record_supported(record: dict[str, Any]) -> bool:
    record_type = record.get("type")
    if record_type in {"session", "model_change"}:
        return True
    if record_type != "message":
        return False
    message = record.get("message")
    if not isinstance(message, dict):
        return False
    role = message.get("role")
    content = message.get("content")
    if role == "toolResult":
        return True
    if role == "user":
        return _message_content_types_supported(content, {"text"}, allow_text=True)
    if role == "assistant":
        return _message_content_types_supported(
            content, {"text", "thinking", "toolCall"}
        )
    return False


def _codex_record_supported(record: dict[str, Any]) -> bool:
    record_type = record.get("type")
    if record_type in {"session_meta", "turn_context"}:
        return True
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return False
    payload_type = payload.get("type")
    if record_type == "event_msg":
        return payload_type in {
            "user_message",
            "agent_message",
            "agent_reasoning",
            "mcp_tool_call_end",
            "token_count",
        }
    if record_type == "response_item":
        return payload_type in {"function_call", "function_call_output"}
    return False


def _unsupported_agent_item(
    record: dict[str, Any], ts: datetime, kind: str
) -> TranscriptItem:
    labels = [str(record.get("type") or "unknown")]
    payload = record.get("payload")
    attachment = record.get("attachment")
    if isinstance(payload, dict) and payload.get("type"):
        labels.append(str(payload["type"]))
    elif isinstance(attachment, dict) and attachment.get("type"):
        labels.append(str(attachment["type"]))
    elif record.get("operation"):
        labels.append(str(record["operation"]))
    message = record.get("message")
    if isinstance(message, dict) and message.get("role") not in {
        None,
        record.get("type"),
    }:
        labels.append(str(message["role"]))

    raw = json.dumps(record, indent=2, ensure_ascii=False, default=str)
    event_name = " · ".join(labels)
    event_html = (
        '<details class="unsupported-event"><summary>'
        '<span class="badge internal">unsupported</span> '
        f"{_e(kind)} · {_e(event_name)}"
        f'<span class="ts">{_e(_format_ts(ts))}</span></summary>'
        f"<pre><code>{_e(raw)}</code></pre></details>"
    )
    return TranscriptItem(ts, "event", event_html)


def _usage_line(usage: dict[str, Any]) -> str:
    parts = [
        f"in {_format_tokens(usage.get('input', 0))}",
        f"out {_format_tokens(usage.get('output', 0))}",
    ]
    cache_read = usage.get("cache_read", 0)
    if cache_read:
        parts.append(f"cache read {_format_tokens(cache_read)}")
    cache_write = usage.get("cache_write", 0)
    if cache_write:
        parts.append(f"cache write {_format_tokens(cache_write)}")
    cost = usage.get("cost")
    if cost is not None:
        parts.append(_format_cost(cost))
    return f'<div class="usage">{" · ".join(_e(p) for p in parts)}</div>'


def _claude_items(records: list[dict]) -> tuple[list[TranscriptItem], dict[str, str]]:
    tool_results: dict[str, object] = {}
    tool_names: dict[str, str] = {}
    for record in records:
        content = record.get("message", {}).get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if not isinstance(item, dict):
                continue
            if record.get("type") == "assistant" and item.get("type") == "tool_use":
                tool_use_id = item.get("id")
                tool_name = item.get("name")
                if isinstance(tool_use_id, str) and isinstance(tool_name, str):
                    tool_names[tool_use_id] = tool_name
            elif record.get("type") == "user" and item.get("type") == "tool_result":
                tool_use_id = item.get("tool_use_id")
                if isinstance(tool_use_id, str):
                    tool_results[tool_use_id] = item.get("content")

    meta: dict[str, str] = {}
    items: list[TranscriptItem] = []
    for record in records:
        record_type = record.get("type")
        ts = _parse_ts(record.get("timestamp"))
        sidechain = "sidechain" if record.get("isSidechain") else ""
        if ts is not None and not _claude_record_supported(record):
            items.append(_unsupported_agent_item(record, ts, "claude"))

        if not meta and record_type in ("user", "assistant"):
            for key in ("sessionId", "cwd", "version", "gitBranch"):
                value = record.get(key)
                if value:
                    meta[key] = str(value)

        if record_type == "user":
            content = record.get("message", {}).get("content")
            texts: list[str] = []
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                texts.extend(
                    str(item.get("text", ""))
                    for item in content
                    if isinstance(item, dict) and item.get("type") == "text"
                )
            for raw in texts:
                text = _SYSTEM_REMINDER_RE.sub("", raw).strip()
                if text:
                    items.append(
                        TranscriptItem(
                            ts,
                            "user",
                            _message_bubble(
                                "user", "user", _render_markdownish(text), ts, sidechain
                            ),
                        )
                    )
            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict) or item.get("type") != "tool_result":
                        continue
                    result_text = _tool_result_text(item.get("content"))
                    if _claude_backgrounded_result(result_text):
                        tag = "backgrounded"
                    elif _claude_truncated_result(result_text):
                        tag = "truncated by agent"
                    else:
                        continue
                    tool_use_id = item.get("tool_use_id")
                    tool_name = (
                        tool_names.get(tool_use_id, "tool")
                        if isinstance(tool_use_id, str)
                        else "tool"
                    )
                    if sidechain:
                        tag += " · sidechain"
                    items.append(
                        TranscriptItem(
                            ts,
                            "status",
                            _message_bubble(
                                _tool_display_name(tool_name),
                                "toolcall",
                                _render_markdownish(result_text),
                                ts,
                                tag,
                            ),
                            tool_name=tool_name,
                        )
                    )
        elif record_type == "assistant":
            message = record.get("message", {})
            model = str(message.get("model", ""))
            record_items: list[TranscriptItem] = []
            for item in message.get("content") or []:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type == "text":
                    text = str(item.get("text", "")).strip()
                    if text:
                        record_items.append(
                            TranscriptItem(
                                ts,
                                "assistant",
                                _message_bubble(
                                    model or "assistant",
                                    "assistant",
                                    _render_markdownish(text),
                                    ts,
                                    sidechain,
                                ),
                            )
                        )
                elif item_type == "thinking":
                    thinking = str(item.get("thinking", "")).strip()
                    if thinking:
                        record_items.append(
                            TranscriptItem(
                                ts,
                                "thinking",
                                f"<details><summary>thinking</summary>"
                                f'<div class="msg"><div class="text">{_e(thinking)}'
                                f"</div></div></details>",
                            )
                        )
                elif item_type == "tool_use":
                    tool_name = str(item.get("name", "tool"))
                    body_parts = [_tool_input_html(tool_name, item.get("input"))]
                    tool_use_id = item.get("id")
                    if tool_use_id in tool_results:
                        result_text = _tool_result_text(tool_results[tool_use_id])
                        if (
                            result_text.strip()
                            and not _claude_backgrounded_result(result_text)
                            and not _claude_truncated_result(result_text)
                        ):
                            body_parts.append(_text_block(result_text, 700, "result"))
                    record_items.append(
                        TranscriptItem(
                            ts,
                            "tool",
                            _message_bubble(
                                _tool_display_name(tool_name),
                                "toolcall",
                                "".join(body_parts),
                                ts,
                                sidechain,
                            ),
                            tool_name=tool_name,
                        )
                    )
            usage = _claude_usage(message.get("usage"), model)
            if usage and record_items:
                # Attribute the record's usage to its first rendered item so it
                # is counted once, and show it inline.
                record_items[0].usage = usage
                record_items[0].html += _usage_line(usage)
            items.extend(record_items)
    return items, meta


def _as_int(value: object) -> int:
    if isinstance(value, (int, float, str)):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _claude_usage(raw: object, model: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    usage = {
        "input": _as_int(raw.get("input_tokens")),
        "output": _as_int(raw.get("output_tokens")),
        "cache_read": _as_int(raw.get("cache_read_input_tokens")),
        "cache_write": _as_int(raw.get("cache_creation_input_tokens")),
        "model": model,
    }
    if not any(usage[k] for k in ("input", "output", "cache_read", "cache_write")):
        return None
    usage["cost"] = _cost_for(model, usage)
    return usage


def _pi_usage(raw: object, model: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    usage = {
        "input": _as_int(raw.get("input")),
        "output": _as_int(raw.get("output")),
        "cache_read": _as_int(raw.get("cacheRead")),
        "cache_write": _as_int(raw.get("cacheWrite")),
        "model": model,
    }
    if not any(usage[k] for k in ("input", "output", "cache_read", "cache_write")):
        return None
    cost = raw.get("cost")
    usage["cost"] = cost.get("total") if isinstance(cost, dict) else None
    return usage


def _pi_active_branch_records(records: list[dict]) -> list[dict]:
    """Select Pi's active tree branch instead of rendering abandoned branches."""
    entries = [
        record
        for record in records
        if record.get("type") != "session" and isinstance(record.get("id"), str)
    ]
    if not entries or any("parentId" not in entry for entry in entries):
        return records  # Legacy linear session or incomplete data.

    by_id = {entry["id"]: entry for entry in entries}
    branch: list[dict] = []
    current: dict | None = entries[-1]
    seen: set[str] = set()
    while current is not None:
        entry_id = current["id"]
        if entry_id in seen:
            return records
        seen.add(entry_id)
        branch.append(current)
        parent_id = current.get("parentId")
        if parent_id is None:
            break
        current = by_id.get(parent_id)
        if current is None:
            return records

    branch.reverse()
    headers = [record for record in records if record.get("type") == "session"]
    return headers + branch


def _pi_items(records: list[dict]) -> tuple[list[TranscriptItem], dict[str, str]]:
    records = _pi_active_branch_records(records)
    tool_results: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.get("type") != "message":
            continue
        message = record.get("message") or {}
        if message.get("role") != "toolResult":
            continue
        tool_call_id = message.get("toolCallId")
        if isinstance(tool_call_id, str):
            tool_results[tool_call_id] = message

    meta: dict[str, str] = {}
    items: list[TranscriptItem] = []
    for record in records:
        record_type = record.get("type")
        ts = _parse_ts(record.get("timestamp"))
        if ts is not None and not _pi_record_supported(record):
            items.append(_unsupported_agent_item(record, ts, "pi"))

        if record_type == "session":
            for key in ("id", "cwd", "version", "parentSession"):
                value = record.get(key)
                if value is not None:
                    meta[key] = str(value)
            continue
        if record_type != "message":
            continue

        message = record.get("message") or {}
        role = message.get("role")
        content = message.get("content")
        if role == "user":
            texts: list[str] = []
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                texts.extend(
                    str(part.get("text", ""))
                    for part in content
                    if isinstance(part, dict) and part.get("type") == "text"
                )
            for text in texts:
                if text.strip():
                    items.append(
                        TranscriptItem(
                            ts,
                            "user",
                            _message_bubble(
                                "user", "user", _render_markdownish(text), ts
                            ),
                        )
                    )
        elif role == "assistant":
            model = str(message.get("model", ""))
            provider = str(message.get("provider", ""))
            who = "/".join(part for part in (provider, model) if part) or "assistant"
            record_items: list[TranscriptItem] = []
            for part in content if isinstance(content, list) else []:
                if not isinstance(part, dict):
                    continue
                part_type = part.get("type")
                if part_type == "text":
                    text = str(part.get("text", "")).strip()
                    if text:
                        record_items.append(
                            TranscriptItem(
                                ts,
                                "assistant",
                                _message_bubble(
                                    who, "assistant", _render_markdownish(text), ts
                                ),
                            )
                        )
                elif part_type == "thinking":
                    thinking = str(part.get("thinking", "")).strip()
                    if thinking:
                        record_items.append(
                            TranscriptItem(
                                ts,
                                "thinking",
                                f"<details><summary>thinking</summary>"
                                f'<div class="msg"><div class="text">{_e(thinking)}'
                                f"</div></div></details>",
                            )
                        )
                elif part_type == "toolCall":
                    tool_name = str(part.get("name", "tool"))
                    body_parts = [_tool_input_html(tool_name, part.get("arguments"))]
                    tool_call_id = part.get("id")
                    result = (
                        tool_results.get(tool_call_id)
                        if isinstance(tool_call_id, str)
                        else None
                    )
                    if result is not None:
                        result_text = _tool_result_text(result.get("content"))
                        if result_text.strip():
                            label = "error" if result.get("isError") else "result"
                            body_parts.append(_text_block(result_text, 700, label))
                    record_items.append(
                        TranscriptItem(
                            ts,
                            "tool",
                            _message_bubble(
                                _tool_display_name(tool_name),
                                "toolcall",
                                "".join(body_parts),
                                ts,
                            ),
                            tool_name=tool_name,
                        )
                    )
            usage = _pi_usage(message.get("usage"), model)
            if usage and record_items:
                record_items[0].usage = usage
                record_items[0].html += _usage_line(usage)
            items.extend(record_items)
    return items, meta


def _codex_items(records: list[dict]) -> tuple[list[TranscriptItem], dict[str, str]]:
    call_outputs: dict[str, str] = {}
    for record in records:
        if record.get("type") != "response_item":
            continue
        payload = record.get("payload") or {}
        if payload.get("type") == "function_call_output":
            call_id = payload.get("call_id")
            if isinstance(call_id, str):
                call_outputs[call_id] = str(payload.get("output", ""))

    meta: dict[str, str] = {}
    items: list[TranscriptItem] = []
    seen_call_ids: set[str] = set()

    for record in records:
        record_type = record.get("type")
        ts = _parse_ts(record.get("timestamp"))
        payload = record.get("payload") or {}
        if ts is not None and not _codex_record_supported(record):
            items.append(_unsupported_agent_item(record, ts, "codex"))

        if record_type == "session_meta":
            for key in ("session_id", "cwd", "cli_version", "model_provider"):
                value = payload.get(key)
                if value:
                    meta[key] = str(value)
        elif record_type == "event_msg":
            event_type = payload.get("type")
            if event_type == "user_message":
                message = str(payload.get("message", "")).strip()
                if message:
                    items.append(
                        TranscriptItem(
                            ts,
                            "user",
                            _message_bubble(
                                "user", "user", _render_markdownish(message), ts
                            ),
                        )
                    )
            elif event_type == "agent_message":
                message = str(payload.get("message", "")).strip()
                if message:
                    items.append(
                        TranscriptItem(
                            ts,
                            "assistant",
                            _message_bubble(
                                "codex", "assistant", _render_markdownish(message), ts
                            ),
                        )
                    )
            elif event_type == "agent_reasoning":
                text = str(payload.get("text", "")).strip()
                if text:
                    items.append(
                        TranscriptItem(
                            ts,
                            "thinking",
                            f"<details><summary>reasoning</summary>"
                            f'<div class="msg"><div class="text">{_e(text)}</div>'
                            f"</div></details>",
                        )
                    )
            elif event_type == "mcp_tool_call_end":
                call_id = payload.get("call_id")
                if isinstance(call_id, str) and call_id in seen_call_ids:
                    continue
                invocation = payload.get("invocation") or {}
                tool_name = (
                    f"{invocation.get('server', '?')}.{invocation.get('tool', '?')}"
                )
                body_parts = [
                    _tool_input_html(
                        str(invocation.get("tool", "")),
                        invocation.get("arguments"),
                    )
                ]
                result = payload.get("result")
                if isinstance(result, dict):
                    ok_content = result.get("Ok")
                    if isinstance(ok_content, dict):
                        result_text = _tool_result_text(ok_content.get("content"))
                        if result_text.strip():
                            body_parts.append(_text_block(result_text, 700, "result"))
                    elif "Err" in result:
                        body_parts.append(_text_block(str(result["Err"]), 700, "error"))
                if isinstance(call_id, str):
                    seen_call_ids.add(call_id)
                items.append(
                    TranscriptItem(
                        ts,
                        "tool",
                        _message_bubble(tool_name, "toolcall", "".join(body_parts), ts),
                        tool_name=tool_name,
                    )
                )
        elif record_type == "response_item":
            item_type = payload.get("type")
            if item_type == "function_call":
                call_id = payload.get("call_id")
                if isinstance(call_id, str):
                    if call_id in seen_call_ids:
                        continue
                    seen_call_ids.add(call_id)
                tool_name = str(payload.get("name", "tool"))
                try:
                    arguments = json.loads(payload.get("arguments", "{}"))
                except (json.JSONDecodeError, TypeError):
                    arguments = payload.get("arguments")
                body_parts = [_tool_input_html(tool_name, arguments)]
                if isinstance(call_id, str) and call_id in call_outputs:
                    output = call_outputs[call_id]
                    if output.strip():
                        body_parts.append(_text_block(output, 700, "output"))
                items.append(
                    TranscriptItem(
                        ts,
                        "tool",
                        _message_bubble(tool_name, "toolcall", "".join(body_parts), ts),
                        tool_name=tool_name,
                    )
                )
    return items, meta


def _codex_session_totals(records: list[dict]) -> dict[str, Any]:
    """Whole-session token totals from the last Codex token_count event.

    Codex records cumulative usage per turn rather than per message, so these
    totals cannot be scoped to a semantic session's time window. OpenAI pricing
    is not tracked, so cost is left unavailable.
    """
    totals = _blank_totals()
    totals["cost"] = None  # OpenAI pricing not tracked; keep cost unavailable
    latest: dict[str, Any] | None = None
    for record in records:
        if record.get("type") != "event_msg":
            continue
        payload = record.get("payload") or {}
        if payload.get("type") == "token_count":
            info = payload.get("info") or {}
            usage = info.get("total_token_usage")
            if isinstance(usage, dict):
                latest = usage
    if latest:
        totals["input"] = int(latest.get("input_tokens", 0) or 0)
        totals["output"] = int(latest.get("output_tokens", 0) or 0)
        totals["cache_read"] = int(latest.get("cached_input_tokens", 0) or 0)
        totals["has_tokens"] = any(totals[k] for k in ("input", "output", "cache_read"))
    return totals


_AgentItemsResult = tuple[
    list[TranscriptItem],
    dict[str, str],
    str,
    dict[str, Any],
]
_AGENT_ITEMS_CACHE: dict[str, tuple[int, int, _AgentItemsResult]] = {}


def _load_agent_items(
    session_path: str,
) -> tuple[list[TranscriptItem], dict[str, str], str, dict[str, Any]]:
    """Return (items, meta, kind, totals) for a transcript file, or empties.

    Results are cached per (path, mtime, size) so the index — which loads the
    same shared transcript for many sessions — parses each file only once.
    """
    path = (
        ARCHIVE_PATH_MAP.get(session_path)
        if ARCHIVE_PATH is not None
        else Path(session_path)
    )
    if path is None or not path.is_file():
        return [], {}, "unknown", _blank_totals()

    try:
        stat = path.stat()
        cache_signature = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        cache_signature = None

    cached = _AGENT_ITEMS_CACHE.get(session_path)
    if (
        cache_signature is not None
        and cached is not None
        and cached[:2] == cache_signature
    ):
        return cached[2]

    records = _read_jsonl(path)
    kind = _detect_agent_kind(records)
    if kind == "codex":
        items, meta = _codex_items(records)
        totals = _codex_session_totals(records)
    elif kind == "pi":
        items, meta = _pi_items(records)
        totals = _blank_totals()
        for item in items:
            if item.usage:
                _add_usage(totals, item.usage)
    else:
        items, meta = _claude_items(records)
        totals = _blank_totals()
        for item in items:
            if item.usage:
                _add_usage(totals, item.usage)

    # Agent files can append queued/background records after later-timestamped
    # events. Keep both recognized and fallback items in timestamp order.
    items.sort(key=lambda item: item.ts or _MIN_DT)

    models = _agent_models(records, kind)
    if models:
        meta["model"] = ", ".join(models)

    result: _AgentItemsResult = (items, meta, kind, totals)
    if cache_signature is not None:
        # Replace the previous revision for this transcript. Active transcript
        # files grow frequently, so retaining every (mtime, size) revision
        # would otherwise keep complete historical renderings forever.
        _AGENT_ITEMS_CACHE[session_path] = (*cache_signature, result)
    return result


def render_agent_session(session_path: str) -> str | None:
    known = _known_agent_sessions()
    if session_path not in known:
        return None
    source_path = Path(session_path)
    path = (
        ARCHIVE_PATH_MAP.get(session_path) if ARCHIVE_PATH is not None else source_path
    )
    if path is None or not path.is_file():
        body = (
            '<div class="empty">Transcript was not included or no longer exists:<br>'
            f"<code>{_e(session_path)}</code></div>"
        )
        return _page("missing transcript — ida-nexus", body)

    items, meta, kind, totals = _load_agent_items(session_path)
    if kind == "pi":
        referenced_kinds = {
            referenced_kind
            for summary in known[session_path]
            for referenced_kind, referenced_path in _summary_agent_sessions(summary)
            if referenced_path == session_path
        }
        if "omp" in referenced_kinds:
            kind = "omp"
    transcript_html = "".join(item.html for item in items)
    unsupported_count = sum(item.category == "event" for item in items)

    related = "".join(
        f'<a href="/session/{quote(_session_route_name(s.path))}">{_e(s.display_target)} '
        f'<span class="mono muted">{_e(s.session_id)}</span></a><br>'
        for s in known[session_path]
    )
    meta_rows = [("Transcript", f'<span class="mono">{_e(session_path)}</span>')]
    meta_rows += [(key, _e(value)) for key, value in meta.items()]
    if totals["has_tokens"]:
        meta_rows.append(("Tokens", _totals_summary_html(totals)))
    meta_rows.append(("Semantic sessions", related or "—"))
    kv = "".join(
        f'<span class="k">{key}</span><span class="v">{value}</span>'
        for key, value in meta_rows
    )

    if not transcript_html:
        transcript_html = '<div class="empty">No renderable messages found.</div>'

    unsupported_control = (
        '<label><input type="checkbox" checked '
        "onchange=\"setVisible('hide-unsupported', this.checked)\"> "
        f"unsupported events ({unsupported_count})</label>"
        if unsupported_count
        else ""
    )
    body = f"""
<div class="crumbs"><a href="/">sessions</a> / {_e(kind)} transcript</div>
<h2><span class="badge {_e(kind)}">{_e(kind)}</span> {_e(_path_name(session_path))}</h2>
<div class="kv">{kv}</div>
<div class="toolbar">
  <button onclick="setAllDetails(true)">expand all</button>
  <button onclick="setAllDetails(false)">collapse all</button>
  {unsupported_control}
</div>
{transcript_html}
"""
    return _page(
        f"{_path_name(session_path)} — ida-nexus",
        body,
        subtitle=f"{kind} session",
    )


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


def _dashboard_host_allowed(bound_host: str, host_header: str | None) -> bool:
    """Reject DNS-rebinding Host values when the dashboard is loopback-bound."""

    if host_header is None:
        return False
    try:
        parsed = urlparse(f"//{host_header}")
        # Accessing port validates malformed or out-of-range port values.
        if parsed.port == 0:
            return False
    except ValueError:
        return False
    if (
        parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False
    return not _is_loopback_host(bound_host) or _is_loopback_host(parsed.hostname)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ida-nexus-dashboard"

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep the console quiet

    def _send_html(self, content: str, status: int = 200) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_download(self, content: str, filename: str) -> None:
        data = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _not_found(self) -> None:
        self._send_html(
            _page("not found — ida-nexus", '<div class="empty">Not found.</div>'),
            status=404,
        )

    def _check_host(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        server_address = getattr(self.server, "server_address", ("", 0))
        bound_host = str(server_address[0]) if isinstance(server_address, tuple) else ""
        if len(hosts) == 1 and _dashboard_host_allowed(bound_host, hosts[0]):
            return True
        self.close_connection = True
        self._send_html(
            _page("forbidden — ida-nexus", '<div class="empty">Forbidden.</div>'),
            status=403,
        )
        return False

    def do_GET(self) -> None:
        if not self._check_host():
            return
        url = urlparse(self.path)
        route = url.path

        try:
            if route == "/":
                self._send_html(render_index())
            elif route.startswith("/session/"):
                page = render_session(route[len("/session/") :])
                self._send_html(page) if page else self._not_found()
            elif route.startswith("/export/session/"):
                name = route[len("/export/session/") :]
                page = render_session(name, export=True)
                if page:
                    self._send_download(page, f"{Path(name).stem}.html")
                else:
                    self._not_found()
            elif route == "/agent":
                params = parse_qs(url.query)
                session_path = (params.get("path") or [""])[0]
                page = render_agent_session(session_path)
                self._send_html(page) if page else self._not_found()
            else:
                self._not_found()
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 -- pragma: no cover - defensive, renders a 500 instead of crashing the handler thread
            self._send_html(
                _page(
                    "error — ida-nexus",
                    f'<div class="empty">Internal error: {_e(exc)}</div>',
                ),
                status=500,
            )


def serve(host: str, port: int, open_browser: bool = False) -> None:
    if not _is_loopback_host(host):
        print(
            "WARNING: dashboard is bound to a non-loopback host without built-in "
            "authentication; session traces may be reachable over the network."
        )

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url = f"http://{host}:{port}/"
    print(f"ida-nexus dashboard: {url}")
    if ARCHIVE_PATH is not None:
        print(f"sessions archive: {ARCHIVE_PATH}")
    else:
        print(f"sessions directory: {SESSIONS_DIR}")
    if open_browser:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()


def cli(argv: list[str] | None = None) -> int:
    global ARCHIVE_PATH, ARCHIVE_PATH_MAP, ARCHIVE_SESSION_AGENT_PATHS
    global ARCHIVE_SOURCE_PATHS, SESSIONS_DIR
    parser = argparse.ArgumentParser(
        prog="ida-nexus dashboard",
        description="Web dashboard for ida-nexus semantic sessions",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--sessions-dir",
        type=Path,
        help="Directory containing semantic session JSONL traces",
    )
    source.add_argument(
        "--archive",
        "--sessions-zip",
        type=Path,
        help="ZIP produced by ida-nexus logs",
    )
    parser.add_argument(
        "--open", action="store_true", help="Open the dashboard in a browser"
    )
    args = parser.parse_args(argv)

    if args.archive is not None:
        try:
            with open_log_archive(args.archive) as archive:
                ARCHIVE_PATH = archive.archive_path
                ARCHIVE_PATH_MAP = archive.path_map
                ARCHIVE_SESSION_AGENT_PATHS = archive.session_agent_paths
                ARCHIVE_SOURCE_PATHS = archive.source_paths
                SESSIONS_DIR = archive.sessions_dir
                _AGENT_ITEMS_CACHE.clear()
                serve(args.host, args.port, open_browser=args.open)
        except (LogArchiveError, OSError) as exc:
            parser.error(str(exc))
        return 0

    ARCHIVE_PATH = None
    ARCHIVE_PATH_MAP = {}
    ARCHIVE_SESSION_AGENT_PATHS = {}
    ARCHIVE_SOURCE_PATHS = {}
    SESSIONS_DIR = (args.sessions_dir or DEFAULT_SESSIONS_DIR).expanduser().resolve()
    _AGENT_ITEMS_CACHE.clear()
    serve(args.host, args.port, open_browser=args.open)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
