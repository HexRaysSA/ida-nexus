import json
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path

from ida_nexus.cli import dashboard
from ida_nexus.cli.logs import (
    ARCHIVE_FORMAT,
    ARCHIVE_SCHEMA,
    TOC_NAME,
    LogArchiveError,
    create_log_archive,
    open_log_archive,
)


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def _semantic_records(session_id: str, agent_path: Path | None = None) -> list[dict]:
    session = {"pi_session_path": str(agent_path)} if agent_path is not None else {}
    return [
        {
            "schema": 1,
            "ts": "2026-01-01T00:00:00+00:00",
            "event": "mcp_started",
            "mcp_server_id": session_id,
            "pid": 999999,
            "agent": "pi",
            "session": session,
        },
        {
            "schema": 1,
            "ts": "2026-01-01T00:00:01+00:00",
            "event": "tool_call",
            "mcp_server_id": session_id,
            "pid": 999999,
            "tool": "reference",
            "session": session,
        },
    ]


def _pi_records() -> list[dict]:
    return [
        {
            "type": "session",
            "version": 3,
            "id": "agent-session",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        {
            "type": "message",
            "id": "message",
            "parentId": None,
            "timestamp": "2026-01-01T00:00:00.5Z",
            "message": {
                "role": "assistant",
                "model": "gpt-5.6",
                "content": [{"type": "text", "text": "archived answer"}],
            },
        },
    ]


@contextmanager
def _dashboard_archive(view):
    original = (
        dashboard.SESSIONS_DIR,
        dashboard.ARCHIVE_PATH,
        dashboard.ARCHIVE_PATH_MAP,
        dashboard.ARCHIVE_SESSION_AGENT_PATHS,
        dashboard.ARCHIVE_SOURCE_PATHS,
    )
    dashboard.SESSIONS_DIR = view.sessions_dir
    dashboard.ARCHIVE_PATH = view.archive_path
    dashboard.ARCHIVE_PATH_MAP = view.path_map
    dashboard.ARCHIVE_SESSION_AGENT_PATHS = view.session_agent_paths
    dashboard.ARCHIVE_SOURCE_PATHS = view.source_paths
    dashboard._AGENT_ITEMS_CACHE.clear()
    try:
        yield
    finally:
        (
            dashboard.SESSIONS_DIR,
            dashboard.ARCHIVE_PATH,
            dashboard.ARCHIVE_PATH_MAP,
            dashboard.ARCHIVE_SESSION_AGENT_PATHS,
            dashboard.ARCHIVE_SOURCE_PATHS,
        ) = original
        dashboard._AGENT_ITEMS_CACHE.clear()


class LogArchiveTests(unittest.TestCase):
    def test_archive_contains_toc_selected_sessions_and_deduplicated_agent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / "agent" / "pi.jsonl"
            first = root / "sessions" / "first.jsonl"
            second = root / "sessions" / "second.jsonl"
            _write_jsonl(agent, _pi_records())
            _write_jsonl(first, _semantic_records("first", agent))
            _write_jsonl(second, _semantic_records("second", agent))

            output = root / "selected.zip"
            result = create_log_archive(output, [second, first])

            self.assertEqual(result.session_count, 2)
            self.assertEqual(result.agent_session_count, 1)
            self.assertEqual(result.missing_agent_sessions, ())
            with zipfile.ZipFile(output) as archive:
                toc = json.loads(archive.read(TOC_NAME))
                self.assertEqual(toc["format"], ARCHIVE_FORMAT)
                self.assertEqual(toc["schema"], ARCHIVE_SCHEMA)
                self.assertEqual(len(toc["sessions"]), 2)
                self.assertEqual(
                    len(
                        [
                            entry
                            for entry in toc["files"]
                            if entry["kind"] == "agent_session"
                        ]
                    ),
                    1,
                )
                self.assertIn(str(first.resolve()), toc["path_map"])
                self.assertIn(str(agent.resolve()), toc["path_map"])
                for entry in toc["files"]:
                    self.assertIn(entry["archive_path"], archive.namelist())
                    self.assertEqual(len(entry["sha256"]), 64)

    def test_archive_collects_conventional_paths_for_any_agent_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            omp_agent = root / "agents" / "omp.jsonl"
            future_agent = root / "agents" / "future.jsonl"
            session = root / "sessions" / "semantic.jsonl"
            _write_jsonl(omp_agent, _pi_records())
            _write_jsonl(future_agent, _pi_records())
            records = _semantic_records("generic")
            linked = {
                "omp_session_path": str(omp_agent),
                "future_agent_session_path": str(future_agent),
                "unrelated_path": str(root / "do-not-collect.jsonl"),
            }
            for record in records:
                record["agent"] = "omp"
                record["session"] = linked
            _write_jsonl(session, records)

            output = root / "generic.zip"
            result = create_log_archive(output, [session])

            self.assertEqual(result.agent_session_count, 2)
            with zipfile.ZipFile(output) as archive:
                toc = json.loads(archive.read(TOC_NAME))
                references = toc["sessions"][0]["agent_sessions"]
                self.assertEqual(
                    {reference["kind"] for reference in references},
                    {"omp", "future_agent"},
                )
                self.assertNotIn(str(root / "do-not-collect.jsonl"), toc["path_map"])

            with open_log_archive(output) as view, _dashboard_archive(view):
                summary = dashboard._scan_sessions()[0]
                self.assertEqual(set(summary.agent_sessions), {"omp", "future_agent"})

    def test_archive_collects_delegated_siblings_without_nexus_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "agents" / "run.jsonl"
            successful_child = root / "agents" / "run" / "Successful.jsonl"
            blocked_child = root / "agents" / "run" / "Blocked.jsonl"
            session = root / "sessions" / "semantic.jsonl"
            _write_jsonl(parent, _pi_records())
            _write_jsonl(successful_child, _pi_records())
            _write_jsonl(blocked_child, _pi_records())
            records = _semantic_records("delegated")
            for record in records:
                record["session"] = {"omp_session_path": str(parent)}
            _write_jsonl(session, records)

            output = root / "delegated.zip"
            result = create_log_archive(output, [session])

            self.assertEqual(result.agent_session_count, 3)
            with zipfile.ZipFile(output) as archive:
                toc = json.loads(archive.read(TOC_NAME))
                references = toc["sessions"][0]["agent_sessions"]
                self.assertEqual(
                    {reference["source_path"] for reference in references},
                    {
                        str(parent.resolve()),
                        str(successful_child.resolve()),
                        str(blocked_child.resolve()),
                    },
                )

    def test_operational_logs_are_included_without_toc_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = root / "sessions" / "semantic.jsonl"
            logs = root / "logs"
            _write_jsonl(session, _semantic_records("with-logs"))
            (logs / "worker.log").parent.mkdir(parents=True)
            (logs / "worker.log").write_bytes(b"worker output\n")
            (logs / "legacy" / "bridge.log").parent.mkdir(parents=True)
            (logs / "legacy" / "bridge.log").write_bytes(b"bridge output\n")

            output = root / "logs.zip"
            result = create_log_archive(output, [session], logs_dir=logs)

            self.assertEqual(result.operational_log_count, 2)
            with zipfile.ZipFile(output) as archive:
                toc = json.loads(archive.read(TOC_NAME))
                self.assertEqual(archive.read("logs/worker.log"), b"worker output\n")
                self.assertEqual(
                    archive.read("logs/legacy/bridge.log"), b"bridge output\n"
                )
                self.assertNotIn(
                    "logs/worker.log",
                    [entry["archive_path"] for entry in toc["files"]],
                )

    def test_default_collection_and_explicit_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "sessions"
            first = sessions / "first.jsonl"
            second = sessions / "second.jsonl"
            _write_jsonl(first, _semantic_records("first"))
            _write_jsonl(second, _semantic_records("second"))
            _write_jsonl(sessions / "not-a-session.jsonl", [{"type": "session"}])

            all_result = create_log_archive(root / "all.zip", sessions_dir=sessions)
            selected_result = create_log_archive(root / "one.zip", [second])

            self.assertEqual(all_result.session_count, 2)
            self.assertEqual(selected_result.session_count, 1)
            with zipfile.ZipFile(root / "one.zip") as archive:
                toc = json.loads(archive.read(TOC_NAME))
                self.assertEqual(
                    toc["sessions"][0]["source_path"], str(second.resolve())
                )

    def test_missing_link_is_recorded_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing-pi.jsonl"
            session = root / "session.jsonl"
            _write_jsonl(session, _semantic_records("missing", missing))

            output = root / "missing.zip"
            result = create_log_archive(output, [session])

            self.assertEqual(len(result.missing_agent_sessions), 1)
            with zipfile.ZipFile(output) as archive:
                toc = json.loads(archive.read(TOC_NAME))
            reference = toc["sessions"][0]["agent_sessions"][0]
            self.assertEqual(reference["recorded_path"], str(missing))
            self.assertIsNone(reference["source_path"])
            self.assertIsNone(reference["archive_path"])

    def test_dashboard_reads_agent_from_archive_after_sources_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / "pi.jsonl"
            session = root / "semantic.jsonl"
            _write_jsonl(agent, _pi_records())
            _write_jsonl(session, _semantic_records("portable", agent))
            output = root / "logs.zip"
            create_log_archive(output, [session])
            agent.unlink()
            session.unlink()

            with open_log_archive(output) as view, _dashboard_archive(view):
                summaries = dashboard._scan_sessions()
                self.assertEqual(
                    [summary.session_id for summary in summaries], ["portable"]
                )
                logical_agent_path = next(
                    path
                    for _kind, path in dashboard._summary_agent_sessions(summaries[0])
                )
                self.assertEqual(logical_agent_path, str(agent.resolve()))
                index = dashboard.render_index()
                agent_page = dashboard.render_agent_session(logical_agent_path)
                session_page = dashboard.render_session(
                    dashboard._session_route_name(summaries[0].path)
                )

            self.assertIn("gpt-5.6", index)
            self.assertIsNotNone(agent_page)
            self.assertIn("archived answer", agent_page or "")
            self.assertIsNotNone(session_page)
            self.assertIn(str(session.resolve()), session_page or "")

    def test_archive_does_not_read_an_unbundled_receiver_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / "not-yet-present.jsonl"
            session = root / "semantic.jsonl"
            _write_jsonl(session, _semantic_records("unbundled", agent))
            output = root / "logs.zip"
            create_log_archive(output, [session])

            # This path exists on the dashboard machine, but it did not exist
            # when the archive was created and therefore is not in its TOC.
            _write_jsonl(agent, _pi_records())
            with open_log_archive(output) as view, _dashboard_archive(view):
                summary = dashboard._scan_sessions()[0]
                logical_agent_path = next(
                    path for _kind, path in dashboard._summary_agent_sessions(summary)
                )
                items, _meta, kind, _totals = dashboard._load_agent_items(
                    logical_agent_path
                )

            self.assertEqual(items, [])
            self.assertEqual(kind, "unknown")

    def test_open_rejects_an_archive_without_the_toc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bad.zip"
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("session.jsonl", "{}\n")

            with (
                self.assertRaisesRegex(LogArchiveError, TOC_NAME),
                open_log_archive(output),
            ):
                pass


if __name__ == "__main__":
    unittest.main()
