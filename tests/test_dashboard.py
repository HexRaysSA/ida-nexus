import json
import os
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

from ida_nexus.cli import dashboard


class TranscriptTests(unittest.TestCase):
    def test_copilot_transcript_renders_messages_tools_and_usage(self) -> None:
        records = [
            {
                "type": "session.start",
                "timestamp": "2026-01-01T00:00:00Z",
                "data": {
                    "sessionId": "copilot-session",
                    "producer": "copilot-agent",
                    "copilotVersion": "1.0.82",
                    "context": {
                        "cwd": "/tmp/project",
                        "repository": "HexRaysSA/ida-mcp",
                        "branch": "main",
                    },
                },
            },
            {
                "type": "user.message",
                "timestamp": "2026-01-01T00:00:01Z",
                "data": {"content": "Look up Database"},
            },
            {
                "type": "assistant.message",
                "timestamp": "2026-01-01T00:00:02Z",
                "data": {
                    "model": "gpt-5.6",
                    "content": "",
                    "toolRequests": [
                        {
                            "toolCallId": "copilot-call",
                            "name": "ida-reference",
                            "arguments": {"query": "Database"},
                        }
                    ],
                },
            },
            {
                "type": "tool.execution_complete",
                "timestamp": "2026-01-01T00:00:03Z",
                "data": {
                    "toolCallId": "copilot-call",
                    "success": True,
                    "result": {"content": "IDA Domain API reference"},
                },
            },
            {
                "type": "assistant.message",
                "timestamp": "2026-01-01T00:00:04Z",
                "data": {
                    "model": "gpt-5.6",
                    "content": "IDA Domain API reference",
                    "toolRequests": [],
                },
            },
            {
                "type": "session.shutdown",
                "timestamp": "2026-01-01T00:00:05Z",
                "data": {
                    "tokenDetails": {
                        "input": {"tokenCount": 11},
                        "output": {"tokenCount": 22},
                        "cache_read": {"tokenCount": 33},
                        "cache_write": {"tokenCount": 44},
                    }
                },
            },
        ]

        self.assertEqual(dashboard._detect_agent_kind(records), "copilot")
        items, meta = dashboard._copilot_items(records)
        totals = dashboard._copilot_session_totals(records)

        self.assertEqual(meta["sessionId"], "copilot-session")
        self.assertEqual(meta["repository"], "HexRaysSA/ida-mcp")
        self.assertEqual(
            [item.category for item in items],
            ["user", "tool", "assistant"],
        )
        tool_item = items[1]
        self.assertEqual(tool_item.tool_name, "ida-reference")
        self.assertIn("ida · reference", tool_item.html)
        self.assertIn("IDA Domain API reference", tool_item.html)
        self.assertEqual(dashboard._nexus_tool_name("ida-reference"), "reference")
        self.assertEqual(
            {
                key: totals[key]
                for key in ("input", "output", "cache_read", "cache_write")
            },
            {"input": 11, "output": 22, "cache_read": 33, "cache_write": 44},
        )
        self.assertTrue(totals["has_tokens"])
        self.assertFalse(totals["cost_available"])

    def test_unknown_copilot_event_remains_visible(self) -> None:
        timestamp = "2026-01-01T00:00:02Z"
        items, _meta = dashboard._copilot_items(
            [
                {
                    "type": "copilot.future_event",
                    "timestamp": timestamp,
                    "data": {"value": "future event value"},
                }
            ]
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].category, "event")
        self.assertEqual(items[0].ts, dashboard._parse_ts(timestamp))
        self.assertIn("copilot · copilot.future_event", items[0].html)
        self.assertIn("future event value", items[0].html)

    def test_active_pi_branch_keeps_tool_names(self) -> None:
        records = [
            {
                "type": "session",
                "version": 3,
                "id": "session-id",
                "timestamp": "2026-01-01T00:00:00Z",
                "cwd": "/tmp/project",
            },
            {
                "type": "message",
                "id": "root",
                "parentId": None,
                "timestamp": "2026-01-01T00:00:01Z",
                "message": {"role": "user", "content": "prompt"},
            },
            {
                "type": "message",
                "id": "call",
                "parentId": "root",
                "timestamp": "2026-01-01T00:00:02Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "toolCall",
                            "id": "ida-call",
                            "name": "ida_execute_python",
                            "arguments": {"code": "lambda: 1"},
                        }
                    ],
                },
            },
            {
                "type": "message",
                "id": "result",
                "parentId": "call",
                "timestamp": "2026-01-01T00:00:03Z",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "ida-call",
                    "toolName": "ida_execute_python",
                    "content": [{"type": "text", "text": "1"}],
                    "isError": False,
                },
            },
        ]
        items, meta = dashboard._pi_items(records)
        self.assertEqual(meta["version"], "3")
        self.assertEqual(
            [item.tool_name for item in items if item.category == "tool"],
            ["ida_execute_python"],
        )
        self.assertIn("ida · execute_python", "".join(item.html for item in items))

    def test_claude_backgrounded_mcp_call_is_a_timed_status(self) -> None:
        tool_name = "mcp__plugin_ida-mcp_ida__execute_python"
        backgrounded = (
            'MCP tool "plugin:ida-mcp:ida/execute_python" is still running after '
            "120s. It was moved to the background as task task-123 and keeps running."
        )
        records = [
            {
                "type": "assistant",
                "timestamp": "2026-01-01T00:00:01Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "claude-call",
                            "name": tool_name,
                            "input": {"code": "result = 1"},
                        }
                    ],
                },
            },
            {
                "type": "user",
                "timestamp": "2026-01-01T00:02:01Z",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "claude-call",
                            "content": [{"type": "text", "text": backgrounded}],
                        }
                    ],
                },
            },
        ]

        items, _meta = dashboard._claude_items(records)

        self.assertEqual([item.category for item in items], ["tool", "status"])
        self.assertNotIn("moved to the background", items[0].html)
        self.assertIn("moved to the background", items[1].html)
        self.assertIn("backgrounded", items[1].html)
        self.assertEqual(items[1].tool_name, tool_name)
        self.assertEqual(items[1].ts, dashboard._parse_ts("2026-01-01T00:02:01Z"))

    def test_claude_result_truncation_is_a_timed_status(self) -> None:
        tool_name = "mcp__plugin_ida-mcp_ida__execute_python"
        notice = (
            "Error: result (235,663 characters) exceeds maximum allowed tokens. "
            "Output has been saved to C:\\tmp\\execute_python.json."
        )
        records = [
            {
                "type": "assistant",
                "timestamp": "2026-01-01T00:00:01Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "claude-call",
                            "name": tool_name,
                            "input": {"code": "result = 1"},
                        }
                    ],
                },
            },
            {
                "type": "user",
                "timestamp": "2026-01-01T00:00:02Z",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "claude-call",
                            "content": notice,
                        }
                    ],
                },
            },
        ]

        items, _meta = dashboard._claude_items(records)

        self.assertEqual([item.category for item in items], ["tool", "status"])
        self.assertNotIn("maximum allowed tokens", items[0].html)
        self.assertIn("maximum allowed tokens", items[1].html)
        self.assertIn("truncated by agent", items[1].html)

    def test_unknown_timestamped_events_render_for_supported_agents(self) -> None:
        unknown_ts = "2026-01-01T00:00:02Z"
        cases = [
            (
                dashboard._claude_items,
                [
                    {
                        "type": "queue-operation",
                        "operation": "enqueue",
                        "timestamp": unknown_ts,
                        "content": "claude queued notification",
                    },
                    {"type": "mode", "mode": "default"},
                ],
                "claude · queue-operation · enqueue",
                "claude queued notification",
            ),
            (
                dashboard._pi_items,
                [
                    {
                        "type": "custom-pi-event",
                        "timestamp": unknown_ts,
                        "value": "pi unknown value",
                    },
                    {"type": "untimed-pi-event"},
                ],
                "pi · custom-pi-event",
                "pi unknown value",
            ),
            (
                dashboard._codex_items,
                [
                    {
                        "type": "event_msg",
                        "timestamp": unknown_ts,
                        "payload": {
                            "type": "custom_codex_event",
                            "value": "codex unknown value",
                        },
                    },
                    {"type": "untimed-codex-event"},
                ],
                "codex · event_msg · custom_codex_event",
                "codex unknown value",
            ),
        ]

        for parser, records, label, raw_value in cases:
            with self.subTest(label=label):
                items, _meta = parser(records)
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0].category, "event")
                self.assertEqual(items[0].ts, dashboard._parse_ts(unknown_ts))
                self.assertIn("unsupported", items[0].html)
                self.assertIn(label, items[0].html)
                self.assertIn(raw_value, items[0].html)

    def test_transcript_cache_replaces_changed_file_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pi.jsonl"
            path.write_text(
                json.dumps({"type": "session", "version": 3, "id": "pi-session"})
                + "\n",
                encoding="utf-8",
            )
            dashboard._AGENT_ITEMS_CACHE.clear()
            first = dashboard._load_agent_items(str(path))

            with path.open("a", encoding="utf-8") as file:
                file.write(
                    json.dumps(
                        {
                            "type": "message",
                            "message": {
                                "role": "assistant",
                                "model": "gpt-5.6",
                                "content": [],
                            },
                        }
                    )
                    + "\n"
                )
            second = dashboard._load_agent_items(str(path))

        self.assertEqual(len(dashboard._AGENT_ITEMS_CACHE), 1)
        self.assertIsNot(first, second)
        self.assertEqual(second[1]["model"], "gpt-5.6")

    def test_extracts_models_from_supported_agent_transcripts(self) -> None:
        self.assertEqual(
            dashboard._agent_models(
                [{"type": "assistant", "message": {"model": "claude-opus-5"}}],
                "claude",
            ),
            ["claude-opus-5"],
        )
        self.assertEqual(
            dashboard._agent_models(
                [
                    {"type": "model_change", "modelId": "gpt-5.6"},
                    {
                        "type": "message",
                        "message": {"role": "assistant", "model": "gpt-5.6"},
                    },
                ],
                "pi",
            ),
            ["gpt-5.6"],
        )
        self.assertEqual(
            dashboard._agent_models(
                [
                    {
                        "type": "turn_context",
                        "payload": {"model": "gpt-5.5"},
                    }
                ],
                "codex",
            ),
            ["gpt-5.5"],
        )
        self.assertEqual(
            dashboard._agent_models(
                [
                    {
                        "type": "session.model_change",
                        "data": {"newModel": "auto"},
                    },
                    {
                        "type": "session.auto_mode_resolved",
                        "data": {"chosenModel": "gpt-5.6-luna"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {"model": "gpt-5.6-luna"},
                    },
                ],
                "copilot",
            ),
            ["gpt-5.6-luna"],
        )


class SessionTimelineTests(unittest.TestCase):
    def test_plugin_install_events_are_rendered(self) -> None:
        events: list[str] = []
        dashboard._add_session_timeline(
            [
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "event": "plugin_install_failed",
                    "mcp_server_id": "s1",
                    "error": {"type": "FileNotFoundError", "message": "not found"},
                }
            ],
            lambda _ts, html: events.append(html),
        )
        self.assertEqual(len(events), 1)
        self.assertIn("plugin_install_failed", events[0])
        self.assertIn("FileNotFoundError", events[0])

    def test_unknown_events_fall_through_generic_else_branch(self) -> None:
        events: list[str] = []
        dashboard._add_session_timeline(
            [
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "event": "some_future_event",
                    "mcp_server_id": "s1",
                    "detail": "unhandled but should still show up",
                }
            ],
            lambda _ts, html: events.append(html),
        )
        self.assertEqual(len(events), 1)
        self.assertIn("some_future_event", events[0])
        self.assertIn("unhandled but should still show up", events[0])

    def test_reference_query_renders_without_collapsed_arguments(self) -> None:
        html = dashboard._render_tool_call_card(
            {
                "ts": "2026-01-01T00:00:00Z",
                "event": "tool_call",
                "call_id": "reference-call",
                "tool": "reference",
                "input": {"query": "EntryInfo attributes"},
            },
            pending=False,
        )
        self.assertIn('<div class="name mono">query</div>', html)
        self.assertIn("EntryInfo attributes", html)
        self.assertNotIn("<summary>arguments", html)

    def test_database_lifecycle_event_links_to_enclosing_open_call(self) -> None:
        call_id = "open-call-id"
        events: list[str] = []
        dashboard._add_session_timeline(
            [
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "event": "tool_call",
                    "call_id": call_id,
                    "tool": "open_database",
                    "input": {"path": "/tmp/sample"},
                },
                {
                    "ts": "2026-01-01T00:00:01Z",
                    "event": "database_opened",
                    "target": {"instance_id": "instance-1"},
                },
                {
                    "ts": "2026-01-01T00:00:02Z",
                    "event": "tool_result",
                    "call_id": call_id,
                    "tool": "open_database",
                    "output": {"instance_id": "instance-1"},
                },
            ],
            lambda _ts, html: events.append(html),
        )
        self.assertEqual(len(events), 3)
        lifecycle = next(event for event in events if "database_opened" in event)
        self.assertIn(f'data-call-id="{call_id}"', lifecycle)


class SemanticSessionTests(unittest.TestCase):
    def test_partial_tool_target_merges_with_database_event_target(self) -> None:
        summary = dashboard.SessionSummary(Path("trace.jsonl"), "trace", 0)
        dashboard._add_target(
            summary,
            {
                "instance_id": "instance-1",
                "record_id": "record-1",
                "idb_path": "/tmp/sample.i64",
                "backend": "idalib",
            },
        )
        dashboard._add_target(
            summary,
            {
                "instance_id": "instance-1",
                "backend": "idalib",
                "status": "current",
            },
        )
        self.assertEqual(len(summary.targets), 1)
        self.assertEqual(summary.targets[0]["idb_path"], "/tmp/sample.i64")
        self.assertEqual(summary.targets[0]["status"], "current")

    def test_tool_completion_distinguishes_model_facing_and_internal_data(self) -> None:
        result = {
            "result": "line one\nline two",
            "stdout": "seven\neight\n",
            "stderr": "",
        }
        call = {
            "event": "tool_call",
            "tool": "execute_python",
            "call_id": "call-id",
            "ts": "2026-01-01T00:00:00Z",
        }
        success_html = dashboard._render_tool_response_card(
            {
                "event": "tool_result",
                "tool": "execute_python",
                "call_id": "call-id",
                "ts": "2026-01-01T00:00:01Z",
                "output": result,
            },
            call,
        )
        self.assertIn("MCP result", success_html)
        self.assertIn("PythonExecutionResult fields", success_html)
        for field in ("result", "stdout"):
            self.assertIn(f'<div class="name mono">{field}</div>', success_html)
        self.assertNotIn('<div class="name mono">stderr</div>', success_html)
        self.assertIn("line one\nline two", success_html)
        self.assertNotIn(r"line one\nline two", success_html)
        self.assertIn("seven\neight\n", success_html)
        self.assertNotIn(r"seven\neight\n", success_html)
        self.assertNotIn("empty string", success_html)
        self.assertNotIn("internal", success_html)

        error = {
            "type": "RemoteError",
            "message": "user failure",
            "traceback": "internal server traceback",
            "code": "execution_failed",
            "status": 400,
            "details": {
                "stdout": "partial output\n",
                "traceback": "user-code traceback\n",
            },
        }
        self.assertEqual(
            dashboard._model_facing_error_payload(error),
            {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "user failure\n\nstdout:\npartial output\n\n"
                            "traceback:\nuser-code traceback"
                        ),
                    }
                ],
                "isError": True,
            },
        )
        error_html = dashboard._render_tool_response_card(
            {
                "event": "tool_error",
                "tool": "execute_python",
                "call_id": "call-id",
                "ts": "2026-01-01T00:00:01Z",
                "error": error,
            },
            call,
        )
        self.assertIn(
            "MCP error JSON; no PythonExecutionResult was returned", error_html
        )
        self.assertIn("server diagnostic metadata", error_html)
        self.assertIn("internal error diagnostic", error_html)
        self.assertLess(error_html.index("model-facing"), error_html.index("internal"))

    def test_session_timeline_interleaves_claude_background_status(self) -> None:
        def write(path: Path, records: list[dict[str, object]]) -> None:
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            transcript = sessions_dir / "claude.jsonl"
            trace = sessions_dir / "trace.jsonl"
            tool_name = "mcp__plugin_ida-mcp_ida__execute_python"
            write(
                transcript,
                [
                    {
                        "type": "assistant",
                        "timestamp": "2026-01-01T00:00:01Z",
                        "message": {
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "tool_use",
                                    "id": "claude-call",
                                    "name": tool_name,
                                    "input": {"code": "result = 1"},
                                }
                            ],
                        },
                    },
                    {
                        "type": "user",
                        "timestamp": "2026-01-01T00:02:01Z",
                        "message": {
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "claude-call",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": (
                                                "It was moved to the background as "
                                                "task task-123 and keeps running."
                                            ),
                                        }
                                    ],
                                }
                            ],
                        },
                    },
                    {
                        "type": "queue-operation",
                        "operation": "enqueue",
                        "timestamp": "2026-01-01T00:02:31Z",
                        "content": "queued failure notification",
                    },
                ],
            )
            session = {"claude_session_path": str(transcript)}
            semantic_call_id = "0123456789abcdef0123456789abcdef"
            write(
                trace,
                [
                    {
                        "schema": 1,
                        "ts": "2026-01-01T00:00:00Z",
                        "event": "mcp_started",
                        "mcp_server_id": "trace",
                        "agent": "claude",
                        "session": session,
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T00:00:01Z",
                        "event": "tool_call",
                        "mcp_server_id": "trace",
                        "call_id": semantic_call_id,
                        "tool": "execute_python",
                        "input": {"code": "result = 1"},
                        "session": session,
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T00:03:01Z",
                        "event": "tool_error",
                        "mcp_server_id": "trace",
                        "call_id": semantic_call_id,
                        "tool": "execute_python",
                        "duration_ms": 180000,
                        "error": {"message": "late failure"},
                        "session": session,
                    },
                ],
            )

            original = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            dashboard._AGENT_ITEMS_CACHE.clear()
            try:
                page = dashboard.render_session(trace.name)
            finally:
                dashboard.SESSIONS_DIR = original
                dashboard._AGENT_ITEMS_CACHE.clear()

        assert page is not None
        call_position = page.index(
            'execute_python <span class="badge muted">started</span>'
        )
        background_position = page.index("moved to the background")
        unsupported_position = page.index("queued failure notification")
        result_position = page.index("late failure")
        self.assertLess(call_position, background_position)
        self.assertLess(background_position, unsupported_position)
        self.assertLess(unsupported_position, result_position)
        self.assertEqual(page.count(f'data-call-id="{semantic_call_id}"'), 2)
        self.assertEqual(page.count("call 01234567…"), 2)
        self.assertIn("MCP error JSON; no PythonExecutionResult was returned", page)
        self.assertIn("server diagnostic metadata", page)
        self.assertIn('type="checkbox" checked', page)
        self.assertIn("transcript (", page)
        self.assertIn("unsupported events (1)", page)

    def test_dashboard_host_policy_blocks_loopback_dns_rebinding(self) -> None:
        for host in ("localhost:8736", "127.0.0.1:8736", "[::1]:8736"):
            self.assertTrue(dashboard._dashboard_host_allowed("127.0.0.1", host))
        self.assertFalse(
            dashboard._dashboard_host_allowed("127.0.0.1", "attacker.example:8736")
        )
        self.assertFalse(dashboard._dashboard_host_allowed("127.0.0.1", None))
        self.assertFalse(
            dashboard._dashboard_host_allowed("127.0.0.1", "localhost:not-a-port")
        )
        # Deliberately remote dashboard bindings retain their existing behavior.
        self.assertTrue(
            dashboard._dashboard_host_allowed("0.0.0.0", "dashboard.example:8736")
        )

    def test_dashboard_handler_enforces_host_policy(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        original_sessions_dir = dashboard.SESSIONS_DIR
        dashboard.SESSIONS_DIR = Path(temporary.name)
        server = dashboard.ThreadingHTTPServer(
            ("127.0.0.1", 0), dashboard.DashboardHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def status(host: str) -> int:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.putrequest("GET", "/", skip_host=True)
                connection.putheader("Host", host)
                connection.endheaders()
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()

        try:
            self.assertEqual(status(f"localhost:{server.server_port}"), 200)
            self.assertEqual(status(f"attacker.example:{server.server_port}"), 403)
        finally:
            server.shutdown()
            thread.join(2)
            server.server_close()
            dashboard.SESSIONS_DIR = original_sessions_dir
            temporary.cleanup()

    def test_pid_liveness_uses_a_safe_windows_probe(self) -> None:
        with (
            mock.patch.object(dashboard.os, "name", "nt"),
            mock.patch.object(
                dashboard, "_windows_pid_alive", return_value=True
            ) as windows_probe,
            mock.patch.object(dashboard.os, "kill") as kill,
        ):
            self.assertTrue(dashboard._pid_alive(1234))

        windows_probe.assert_called_once_with(1234)
        kill.assert_not_called()
        self.assertFalse(dashboard._pid_alive(0))

        if os.name == "nt":
            self.assertTrue(dashboard._windows_pid_alive(os.getpid()))

    def test_pid_liveness_handles_a_broken_posix_probe(self) -> None:
        with (
            mock.patch.object(dashboard.os, "name", "posix"),
            mock.patch.object(
                dashboard.os,
                "kill",
                side_effect=SystemError(
                    "<built-in function kill> returned a result with an exception set"
                ),
            ),
        ):
            self.assertFalse(dashboard._pid_alive(1234))

    def test_scan_hides_traces_without_tool_or_agent_activity(self) -> None:
        def write(path: Path, records: list[dict[str, object]]) -> None:
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

        base = {
            "schema": 1,
            "ts": "2026-01-01T00:00:00Z",
            "pid": 999999,
        }
        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            agent_path = sessions_dir / "agent.trace"
            write(
                agent_path,
                [
                    {"type": "session", "version": 3, "id": "pi-session"},
                    {
                        "type": "message",
                        "message": {"role": "assistant", "model": "gpt-5.6"},
                    },
                ],
            )
            write(
                sessions_dir / "empty.jsonl",
                [{**base, "event": "mcp_stopped", "mcp_server_id": "empty"}],
            )
            write(
                sessions_dir / "lifecycle.jsonl",
                [
                    {
                        **base,
                        "event": "database_opened",
                        "mcp_server_id": "lifecycle",
                        "target": {"idb_path": "/tmp/pytest/open.i64"},
                    }
                ],
            )
            write(
                sessions_dir / "tool.jsonl",
                [
                    {
                        **base,
                        "event": "tool_call",
                        "mcp_server_id": "tool",
                        "tool": "reference",
                    }
                ],
            )
            write(
                sessions_dir / "agent.jsonl",
                [
                    {
                        **base,
                        "event": "mcp_started",
                        "mcp_server_id": "agent",
                        "agent": "pi",
                        "session": {"pi_session_path": str(agent_path)},
                    }
                ],
            )

            original = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            try:
                summaries = dashboard._scan_sessions()
                index = dashboard.render_index()
            finally:
                dashboard.SESSIONS_DIR = original

        self.assertIn("gpt-5.6", index)
        self.assertEqual(
            next(s.agent for s in summaries if s.session_id == "agent"), "pi"
        )
        self.assertEqual(
            {summary.session_id for summary in summaries},
            {"tool", "agent"},
        )

    def test_omp_session_path_uses_omp_agent_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            agent_path = sessions_dir / "omp.trace"
            agent_path.write_text(
                "\n".join(
                    json.dumps(record)
                    for record in [
                        {
                            "type": "session",
                            "version": 3,
                            "id": "omp-session",
                            "timestamp": "2026-01-01T00:00:00Z",
                            "cwd": "/tmp/project",
                        },
                        {
                            "type": "message",
                            "id": "assistant",
                            "parentId": None,
                            "timestamp": "2026-01-01T00:00:01Z",
                            "message": {
                                "role": "assistant",
                                "model": "gpt-5.6",
                                "content": [{"type": "text", "text": "done"}],
                            },
                        },
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (sessions_dir / "omp.jsonl").write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "ts": "2026-01-01T00:00:02Z",
                        "pid": 999999,
                        "event": "mcp_started",
                        "mcp_server_id": "omp-server",
                        "agent": "omp",
                        "session": {"omp_session_path": str(agent_path)},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            original = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            dashboard._AGENT_ITEMS_CACHE.clear()
            try:
                summary = dashboard._scan_sessions()[0]
                index = dashboard.render_index()
                transcript = dashboard.render_agent_session(str(agent_path))
            finally:
                dashboard.SESSIONS_DIR = original
                dashboard._AGENT_ITEMS_CACHE.clear()

        self.assertEqual(summary.agent, "omp")
        self.assertEqual(
            summary.agent_session_refs,
            {("omp", str(agent_path))},
        )
        self.assertIn('class="badge omp"', index)
        self.assertIsNotNone(transcript)
        assert transcript is not None
        self.assertIn("omp transcript", transcript)
        self.assertIn('class="badge omp"', transcript)

    def test_benchmark_autodetect_and_agent_resolution(self) -> None:
        def write(path: Path, records: list[dict[str, object]]) -> None:
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

        base = {
            "schema": 1,
            "ts": "2026-01-01T00:00:00Z",
            "pid": 999999,
        }
        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            run_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            run_dir = sessions_dir / run_id
            logs_dir = run_dir / "logs"
            mcp_dir = logs_dir / "ida-nexus"
            mcp_dir.mkdir(parents=True)

            (run_dir / "result.json").write_text("{}", encoding="utf-8")

            write(
                logs_dir / "session.jsonl",
                [
                    {"type": "user", "message": {"role": "user", "content": "hi"}},
                    {
                        "type": "assistant",
                        "message": {
                            "role": "assistant",
                            "model": "claude-opus-5",
                            "content": [{"type": "text", "text": "hello"}],
                        },
                    },
                ],
            )

            write(
                mcp_dir / "session.jsonl",
                [
                    {
                        **base,
                        "event": "mcp_started",
                        "mcp_server_id": "bench-test",
                        "agent": "claude-code",
                        "session": {
                            "claude_session_path": "/root/.claude/nonexistent.jsonl",
                        },
                    },
                    {
                        **base,
                        "event": "tool_call",
                        "mcp_server_id": "bench-test",
                        "tool": "execute_python",
                    },
                ],
            )

            original_dir = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            try:
                self.assertTrue(dashboard._is_benchmark_dir(sessions_dir))
                summaries = dashboard._scan_sessions()
                index = dashboard.render_index()
                self.assertEqual(len(summaries), 1)
                self.assertIn("bench-test", index)
                summary = summaries[0]
                self.assertEqual(summary.session_id, "bench-test")
                resolved = summary.agent_sessions.get("claude")
                assert resolved is not None
                self.assertEqual(
                    Path(resolved),
                    logs_dir / "session.jsonl",
                )
            finally:
                dashboard.SESSIONS_DIR = original_dir

    def test_schema_validation_rejects_non_matching_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            (sessions_dir / "random.jsonl").write_text(
                '{"foo": "bar"}\n', encoding="utf-8"
            )
            (sessions_dir / "empty.jsonl").write_text("", encoding="utf-8")
            (sessions_dir / "bad.jsonl").write_text("not json\n", encoding="utf-8")

            original = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            try:
                summaries = dashboard._scan_sessions()
            finally:
                dashboard.SESSIONS_DIR = original

            self.assertEqual(len(summaries), 0)


if __name__ == "__main__":
    unittest.main()
