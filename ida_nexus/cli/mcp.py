"""Command-line entry point for the reusable IDA Nexus MCP server."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from ida_nexus.mcp import (
    MCP_IDLE_TIMEOUT_ENVIRONMENT_VARIABLE,
    _mcp_idle_timeout_from_environment,
    serve_http,
    serve_stdio,
)


def _report_claude_session(payload: dict[str, object]) -> dict[str, object]:
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


def _report_codex_session(payload: dict[str, object]) -> dict[str, object]:
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


def _report_copilot_session(payload: dict[str, object]) -> dict[str, object]:
    tool_args = payload.get("toolArgs")
    if not isinstance(tool_args, dict):
        tool_args = {}

    existing_meta = tool_args.get("_meta")
    if not isinstance(existing_meta, dict):
        existing_meta = {}

    updated_args = dict(tool_args)
    updated_meta = dict(existing_meta)
    session_id = payload.get("sessionId")
    if isinstance(session_id, str) and session_id:
        configured_home = os.environ.get("COPILOT_HOME")
        copilot_home = (
            Path(configured_home).expanduser()
            if configured_home
            else Path.home() / ".copilot"
        )
        transcript_path = copilot_home / "session-state" / session_id / "events.jsonl"
        updated_meta["copilot_session_path"] = str(transcript_path)
    if updated_meta:
        updated_args["_meta"] = updated_meta

    return {
        "permissionDecision": "allow",
        "modifiedArgs": updated_args,
    }


def _report_session_main(platform: str) -> int:
    """Inject agent transcript/session metadata into a PreToolUse tool input."""

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"report-session: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("report-session: input must be a JSON object", file=sys.stderr)
        return 1

    if platform == "claude":
        response = _report_claude_session(payload)
    elif platform == "codex":
        response = _report_codex_session(payload)
    elif platform == "copilot":
        response = _report_copilot_session(payload)
    else:
        print(f"report-session: unsupported platform: {platform}", file=sys.stderr)
        return 2

    print(json.dumps(response))
    return 0


def _idle_timeout(value: str) -> float | None:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("idle timeout must be a number") from exc
    if timeout == 0:
        return None
    if not timeout > 0 or timeout == float("inf"):
        raise argparse.ArgumentTypeError(
            "idle timeout must be positive and finite, or zero to disable"
        )
    return timeout


def _http_target(transport: str) -> tuple[str, int]:
    url = urlparse(transport)
    if url.scheme not in {"http", "https"} or url.hostname is None or url.port is None:
        raise ValueError(f"Invalid transport URL: {transport}")
    if url.path not in {"", "/"} or url.params or url.query or url.fragment:
        raise ValueError("HTTP transport URL must not contain a path")
    return url.hostname, url.port


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
        "--idle-timeout",
        type=_idle_timeout,
        default=_mcp_idle_timeout_from_environment(),
        help=(
            "Release each managed idalib lease after this many seconds without "
            "a database request; zero disables idle release. Defaults to no "
            "timeout. Can also be set with "
            f"{MCP_IDLE_TIMEOUT_ENVIRONMENT_VARIABLE}."
        ),
    )
    parser.add_argument(
        "--report-session",
        choices=["claude", "codex", "copilot"],
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)

    if args.report_session is not None:
        return _report_session_main(args.report_session)

    if args.transport == "stdio":
        serve_stdio(
            database=args.database,
            agent=args.agent,
            idle_timeout=args.idle_timeout,
        )
        return 0

    try:
        host, port = _http_target(args.transport)
    except ValueError as exc:
        parser.error(str(exc))

    options = {
        "agent": args.agent,
        "database": args.database,
        "idle_timeout": args.idle_timeout,
    }

    print("Server is running; press Ctrl+C to stop.", file=sys.stderr)
    serve_http(host, port, background=False, **options)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
