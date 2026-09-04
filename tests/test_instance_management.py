import argparse
import asyncio
import json
import os
import subprocess
import threading
import time
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import ida_nexus._resolver as resolver_mod
import ida_nexus.handle as client_mod
from ida_nexus import (
    DatabaseChangeSubscription,
    DatabaseDisconnectedError,
    DatabaseHandle,
    DatabaseManager,
    DatabaseOpenOptions,
    DatabaseSelectionError,
    NexusConnectionError,
    PythonExecutionResult,
    discover_databases,
    find_database_owner,
    wait_database_released,
)
from ida_nexus import mcp as mcp_app
from ida_nexus._http import RequestHandler
from ida_nexus._registry import (
    PROTOCOL_VERSION,
    REGISTRY_DIR,
    DatabaseInstance,
    FileLock,
    InstanceIdentity,
    InstanceRegistration,
    InstanceState,
    canonical_path,
    find_gui_owner,
    scan_instances,
)
from ida_nexus._resolver import resolve_instance
from ida_nexus._runtime import AnalysisState, IdbChangeState
from ida_nexus._server import NexusHTTPServer
from ida_nexus.cli.worker import (
    _build_ida_options,
    _image_base_to_paragraphs,
    _parse_image_base,
    _work_around_idapro_idausr_path_list,
)
from ida_nexus.cli.worker import (
    _parser as worker_parser,
)


class StaticBackend:
    def __init__(self) -> None:
        self.idb_change_state = IdbChangeState()

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
        flush_database: bool = False,
    ) -> PythonExecutionResult:
        del lease_id, operation_id, operation_label, persist_globals, flush_database
        return {
            "result": {"code": code, "timeout": timeout},
            "stdout": "",
            "stderr": "",
        }

    def cancel_active(self) -> None:
        pass

    def release_session(self, lease_id: str) -> None:
        del lease_id

    def advance_autoanalysis(self):
        return {"status": "complete", "complete": True}

    def wait_autoanalysis(self, timeout: float | None):
        return {"status": "complete", "complete": True}

    def save_database(self):
        return {"saved": True, "idb_path": "/tmp/test.i64"}

    def enable_idb_change_hook(self) -> None:
        pass

    def disable_idb_change_hook(self) -> None:
        pass

    def subscribe_idb_changes(self):
        return self.idb_change_state.subscribe()

    def wait_idb_change(self, subscriber, timeout: float):
        return self.idb_change_state.wait(subscriber, timeout)

    def record_idb_change(
        self,
        operation_id: str | None = None,
        operation_label: str | None = None,
        origin_id: str | None = None,
    ) -> None:
        self.idb_change_state.record(
            {"event_name": operation_id or "changed", "timestamp": 1},
            operation_id,
            operation_label,
            origin_id,
        )


def test_file_lock_excludes_other_open_descriptions(tmp_path: Path) -> None:
    first = FileLock(tmp_path / "test.lock")
    second = FileLock(tmp_path / "test.lock")
    first.acquire(0)
    try:
        assert second.try_acquire() is False
    finally:
        second.close()
        first.close()


def test_lifecycle_apis_reject_nonfinite_timeouts(tmp_path: Path) -> None:
    for timeout in (float("nan"), float("inf")):
        lock = FileLock(tmp_path / "invalid.lock")
        try:
            lock.acquire(timeout)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid lock timeout: {timeout}")

        try:
            resolve_instance(
                tmp_path / "missing.exe",
                timeout=timeout,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid resolver timeout: {timeout}")

        parameter_sets = (
            ("open", timeout, 1.0),
            ("execute", 1.0, timeout),
        )
        for name, open_timeout, execute_timeout in parameter_sets:
            try:
                DatabaseManager(
                    open_timeout=open_timeout,
                    execute_timeout=execute_timeout,
                )
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted invalid {name} timeout: {timeout}")


def test_find_gui_owner_checks_the_lifetime_lock(tmp_path: Path) -> None:
    registration = InstanceRegistration(
        tmp_path,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        token="token",
    )
    entry = registration.publish(12345)
    try:
        assert find_gui_owner("/tmp/test.i64", tmp_path) == entry
        assert find_gui_owner("/tmp/other.i64", tmp_path) is None

        registration.lock.close()  # Simulate the owning process exiting.
        assert find_gui_owner("/tmp/test.i64", tmp_path) is None
    finally:
        registration.release()


def test_scan_reaps_a_record_after_its_lifetime_lock_dies(tmp_path: Path) -> None:
    registration = InstanceRegistration(
        tmp_path,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib"),
        token="token",
    )
    entry = registration.publish(12345)
    registration.lock.close()  # Simulate kernel release after a hard process exit.
    assert (tmp_path / f"{entry.record_id}.json").exists()

    assert scan_instances(tmp_path, timeout=0.01) == []
    assert not (tmp_path / f"{entry.record_id}.json").exists()
    registration.release()


def test_scan_blocks_an_unsupported_protocol_version(tmp_path: Path) -> None:
    registry_dir = REGISTRY_DIR
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    unsupported = replace(server.entry, version=PROTOCOL_VERSION + 1)
    server._entry = unsupported
    record_path = registry_dir / f"{unsupported.record_id}.json"
    record_path.write_text(
        json.dumps(unsupported._registry_payload()), encoding="utf-8"
    )

    try:
        discovered = scan_instances(registry_dir)
    finally:
        server.stop()
        server.release_registration()

    assert len(discovered) == 1
    assert discovered[0].instance == unsupported
    assert discovered[0].state is InstanceState.BLOCKED
    assert discovered[0].detail == (
        f"unsupported protocol version {PROTOCOL_VERSION + 1}; "
        f"expected {PROTOCOL_VERSION}"
    )


def test_scan_accepts_additive_protocol_fields() -> None:
    registry_dir = REGISTRY_DIR
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    entry = server.entry
    record_path = registry_dir / f"{entry.record_id}.json"
    payload = json.loads(record_path.read_text(encoding="utf-8"))
    payload["future_registry_field"] = {"optional": True}
    record_path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        discovered = scan_instances(registry_dir)
    finally:
        server.stop()
        server.release_registration()

    assert len(discovered) == 1
    assert discovered[0].instance == entry
    assert discovered[0].state is InstanceState.READY


def test_resolver_timeout_is_shared_across_registry_probes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_dir = REGISTRY_DIR
    registrations = [
        InstanceRegistration(
            registry_dir,
            InstanceIdentity(
                f"/tmp/unrelated-{index}.i64",
                f"/tmp/unrelated-{index}",
                "gui",
            ),
            token=f"token-{index}",
        )
        for index in range(2)
    ]
    for index, registration in enumerate(registrations):
        registration.publish(12000 + index)

    def slow_probe(_entry, timeout: float):
        time.sleep(timeout)
        return False, "timeout"

    monkeypatch.setattr("ida_nexus._registry.probe_health", slow_probe)
    started = time.monotonic()
    try:
        try:
            resolve_instance(
                tmp_path / "missing.exe",
                spawn=False,
                timeout=0.05,
            )
        except TimeoutError:
            pass
        else:  # pragma: no cover
            raise AssertionError("expected the resolver deadline to expire")
    finally:
        for registration in registrations:
            registration.release()

    # The timeout is one budget for the whole scan, not one budget per record.
    assert time.monotonic() - started < 0.15


def test_worker_autoanalysis_starts_by_default() -> None:
    assert DatabaseOpenOptions().auto_analysis is True
    assert resolver_mod.WorkerLaunchOptions().auto_analysis is True
    assert worker_parser().parse_args(["sample.bin"]).auto_analysis is True
    assert (
        worker_parser().parse_args(["sample.bin", "--no-auto-analysis"]).auto_analysis
        is False
    )


def test_database_handle_forwards_import_options(monkeypatch) -> None:
    captured = {}
    entry = SimpleNamespace(record_id="test-entry")

    def fake_resolve(path, **options):
        captured.update(path=path, options=options)
        return entry

    class CapturingHandle(DatabaseHandle):
        def __init__(
            self,
            path,
            resolved_entry,
            keepalive=0,
            idle_timeout=None,
            recovery="none",
            on_disconnect=None,
        ):
            self.opened = (
                path,
                resolved_entry,
                keepalive,
                idle_timeout,
                on_disconnect,
                recovery,
            )

    monkeypatch.setattr(client_mod, "resolve_instance", fake_resolve)
    handle = CapturingHandle.open(
        "firmware.bin",
        options=DatabaseOpenOptions(
            output_database="firmware.i64",
            idle_timeout=30,
            auto_analysis=True,
            image_base=0x8000,
            new_database=True,
            compiler="gcc",
            first_pass_directives=("FIRST=1",),
            second_pass_directives=("SECOND=1",),
            disable_fpp=True,
            entry_point=0x8010,
            jit_debugger=False,
            log_file="ida.log",
            disable_mouse=True,
            plugin_options="sample:option",
            processor="arm",
            db_compression="pack",
            run_debugger="linux",
            load_resources=True,
            script_file="startup.py",
            script_args=("arg",),
            file_type="ZIP",
            file_member="nested.bin",
            empty_database=True,
            windows_dir="windows",
            no_segmentation=True,
            debug_flags=("ldr",),
        ),
    )

    assert handle.opened[:4] == ("firmware.bin", entry, 0.0, 30)
    assert handle.opened[5] == "none"
    assert captured["path"] == "firmware.bin"
    assert captured["options"] == {
        "spawn": True,
        "timeout": 120.0,
        "output_database": "firmware.i64",
        "auto_analysis": True,
        "image_base": 0x8000,
        "new_database": True,
        "compiler": "gcc",
        "first_pass_directives": ("FIRST=1",),
        "second_pass_directives": ("SECOND=1",),
        "disable_fpp": True,
        "entry_point": 0x8010,
        "jit_debugger": False,
        "log_file": "ida.log",
        "disable_mouse": True,
        "plugin_options": "sample:option",
        "processor": "arm",
        "db_compression": "pack",
        "run_debugger": "linux",
        "load_resources": True,
        "script_file": "startup.py",
        "script_args": ("arg",),
        "file_type": "ZIP",
        "file_member": "nested.bin",
        "empty_database": True,
        "windows_dir": "windows",
        "no_segmentation": True,
        "debug_flags": ("ldr",),
    }


def test_resolver_builds_worker_import_options(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    output = tmp_path / "analysis" / "firmware.i64"
    source.write_bytes(b"binary")
    captured = {}
    servers: list[NexusHTTPServer] = []

    def fake_spawner(
        source_path: str,
        expected_idb: str,
        lease_grace: float,
        options: resolver_mod.WorkerLaunchOptions,
    ) -> tuple[subprocess.Popen[bytes], Path]:
        captured.update(
            source=source_path,
            expected_idb=expected_idb,
            lease_grace=lease_grace,
            options=options,
        )
        server = NexusHTTPServer(
            StaticBackend(),
            InstanceIdentity(expected_idb, source_path, "idalib"),
            AnalysisState(),
            REGISTRY_DIR,
        )
        server.start()
        servers.append(server)
        process = cast(
            subprocess.Popen[bytes],
            SimpleNamespace(pid=os.getpid(), poll=lambda: None),
        )
        return process, tmp_path / "worker.log"

    try:
        result = resolve_instance(
            source,
            output_database=output,
            auto_analysis=True,
            image_base=0x8000,
            new_database=True,
            compiler="gcc",
            first_pass_directives="FIRST=1",
            second_pass_directives=["SECOND=1"],
            disable_fpp=True,
            entry_point=0x8010,
            jit_debugger=False,
            log_file=tmp_path / "ida.log",
            disable_mouse=True,
            plugin_options="sample:option",
            processor="arm",
            db_compression="no_pack",
            run_debugger="linux",
            load_resources=True,
            script_file=tmp_path / "startup.py",
            script_args="argument",
            file_type="ZIP",
            file_member="nested.bin",
            empty_database=True,
            windows_dir=tmp_path / "windows",
            no_segmentation=True,
            debug_flags="ldr",
            spawner=fake_spawner,
        )
        assert servers[0].entry == result
    finally:
        for server in servers:
            server.stop()
            server.release_registration()

    assert captured["source"] == str(source.resolve())
    assert captured["expected_idb"] == str(output.resolve())
    assert captured["options"] == resolver_mod.WorkerLaunchOptions(
        auto_analysis=True,
        image_base=0x8000,
        new_database=True,
        compiler="gcc",
        first_pass_directives=("FIRST=1",),
        second_pass_directives=("SECOND=1",),
        disable_fpp=True,
        entry_point=0x8010,
        jit_debugger=False,
        log_file=str(tmp_path / "ida.log"),
        disable_mouse=True,
        plugin_options="sample:option",
        processor="arm",
        db_compression="no_pack",
        run_debugger="linux",
        load_resources=True,
        script_file=str(tmp_path / "startup.py"),
        script_args=("argument",),
        file_type="ZIP",
        file_member="nested.bin",
        empty_database=True,
        windows_dir=str(tmp_path / "windows"),
        no_segmentation=True,
        debug_flags=("ldr",),
    )


def test_handle_close_does_not_wait_for_sse_heartbeat(tmp_path: Path) -> None:
    executable = tmp_path / "sample.exe"
    idb_path = tmp_path / "sample.exe.i64"
    executable.write_bytes(b"binary")
    idb_path.write_bytes(b"idb")
    registry_dir = REGISTRY_DIR
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
        heartbeat_interval=30.0,
    )
    server.start()
    handle = DatabaseHandle.open(
        str(executable),
        options=DatabaseOpenOptions(spawn=False),
    )
    try:
        # Let the monitor consume the initial event and block waiting for the
        # deliberately distant heartbeat.
        time.sleep(0.05)
        started = time.monotonic()
        handle.close()
        elapsed = time.monotonic() - started
        assert elapsed < 1.0
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_public_discovery_owner_and_release_api(tmp_path: Path) -> None:
    executable = tmp_path / "sample.exe"
    idb_path = tmp_path / "sample.exe.i64"
    executable.write_bytes(b"binary")
    idb_path.write_bytes(b"idb")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    server.start()
    assert server.entry is not None
    instance = server.entry
    try:
        discovered = discover_databases()
        assert [item.instance for item in discovered] == [instance]
        assert find_database_owner(executable) == instance
        assert find_database_owner(idb_path) == instance
        assert not wait_database_released(instance, timeout=0)
    finally:
        server.stop()
        server.release_registration()
    assert wait_database_released(instance, timeout=1)


def test_resolver_prefers_gui_executable_identity(tmp_path: Path) -> None:
    executable = tmp_path / "sample.exe"
    funny_idb = tmp_path / "saved-elsewhere.i64"
    executable.write_bytes(b"binary")
    funny_idb.write_bytes(b"idb")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(funny_idb), str(executable), "gui"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    server.start()
    try:
        entry = resolve_instance(
            executable,
            spawn=False,
        )
        assert entry.backend == "gui"
        assert entry.idb_path.endswith("saved-elsewhere.i64")
        try:
            resolve_instance(
                executable,
                spawn=False,
                new_database=True,
            )
        except resolver_mod.DatabaseBusyError as exc:
            assert "cannot create a fresh database" in str(exc)
        else:
            raise AssertionError("fresh open reused a live GUI owner")
    finally:
        server.stop()
        server.release_registration()


def test_mcp_unsets_empty_forwarded_environment_variables(monkeypatch) -> None:
    monkeypatch.setenv("IDA_NEXUS_ID", "")
    monkeypatch.setenv("IDAUSR", "/tmp/ida-user")
    monkeypatch.setenv("IDA_NEXUS_STATE_DIR", "")

    mcp_app._unset_empty_environment_variables()

    assert "IDA_NEXUS_ID" not in mcp_app.os.environ
    assert mcp_app.os.environ["IDAUSR"] == "/tmp/ida-user"
    assert "IDA_NEXUS_STATE_DIR" not in mcp_app.os.environ


def test_mcp_gui_plugin_requires_current_or_newer_version(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins" / "ida-nexus"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "ida_nexus_plugin.py").touch()
    manifest = plugin_dir / "ida-plugin.json"

    cases = {
        "1.2.2": False,
        "1.2.3-dev.1": False,
        "1.2.3-dev.2": True,
        "1.2.3": True,
        "1.3.0": True,
    }
    for plugin_version, expected in cases.items():
        manifest.write_text(
            json.dumps({"plugin": {"version": plugin_version}}), encoding="utf-8"
        )
        assert mcp_app._compatible_gui_plugin(plugin_dir, "1.2.3.dev2") is expected


def test_mcp_gui_plugin_rejects_missing_or_invalid_version(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins" / "ida-nexus"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "ida_nexus_plugin.py").touch()
    manifest = plugin_dir / "ida-plugin.json"

    assert mcp_app._compatible_gui_plugin(plugin_dir, "1.2.3") is False
    for contents in ("not json", "{}", '{"plugin":{"version":"invalid"}}'):
        manifest.write_text(contents, encoding="utf-8")
        assert mcp_app._compatible_gui_plugin(plugin_dir, "1.2.3") is False


def test_mcp_recognizes_consumer_gui_provider(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins" / "ida-mcp"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "ida_mcp_plugin.py").touch()
    (plugin_dir / "ida-plugin.json").write_text(
        json.dumps(
            {
                "plugin": {
                    "name": "ida-mcp",
                    "entryPoint": "ida_mcp_plugin.py",
                    "pythonDependencies": ["ida-nexus>=0.7.0"],
                }
            }
        ),
        encoding="utf-8",
    )

    assert mcp_app._declares_nexus_gui_provider(plugin_dir, "ida-mcp") is True
    assert mcp_app._declares_nexus_gui_provider(plugin_dir, "ida-chat") is False


def test_pi_package_includes_runtime_peers_and_gui_manifest() -> None:
    root = Path(__file__).parents[1]
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    assert package["peerDependencies"]["@earendil-works/pi-tui"] == "*"
    assert "ida-plugin.json" in package["files"]


def test_mcp_execute_owns_autoanalysis_policy(monkeypatch) -> None:
    class FakeManager:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        def resolve_instance_id(self, instance_id: str | None) -> str:
            self.calls.append(("resolve_instance_id", instance_id))
            assert instance_id is not None
            return instance_id

        def ensure_autoanalysis(
            self,
            instance_id: str | None,
            *,
            operation_id: str | None = None,
        ) -> None:
            self.calls.append(("ensure_autoanalysis", instance_id, operation_id))

        def execute_python(
            self,
            code: str,
            instance_id: str | None,
            timeout: float | None = None,
            *,
            operation_id: str | None = None,
            operation_label: str | None = None,
            persist_globals: bool = False,
        ):
            assert persist_globals
            self.calls.append(
                (
                    "execute_python",
                    code,
                    instance_id,
                    timeout,
                    operation_id,
                    operation_label,
                )
            )
            return {"result": 1, "stdout": "", "stderr": ""}

    manager = FakeManager()
    trace_records: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(
            emit=lambda event, **fields: trace_records.append((event, fields))
        ),
    )

    result = asyncio.run(mcp_app.execute_python("lambda: 1", "test-instance"))
    assert result == {
        "result": 1,
        "stdout": "",
        "stderr": "",
    }
    assert manager.calls[0] == ("resolve_instance_id", "test-instance")
    operation_id = manager.calls[1][2]
    assert isinstance(operation_id, str) and len(operation_id) == 32
    tool_call = next(fields for event, fields in trace_records if event == "tool_call")
    assert operation_id == tool_call["call_id"]
    assert manager.calls[1:] == [
        ("ensure_autoanalysis", "test-instance", operation_id),
        (
            "execute_python",
            "lambda: 1",
            "test-instance",
            360,
            operation_id,
            "ida-nexus mcp",
        ),
    ]


def test_mcp_execute_honors_cancellation_notification(monkeypatch) -> None:
    class BlockingManager:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()
            self.executed = threading.Event()
            self.cancel_calls: list[tuple[str, str]] = []

        @staticmethod
        def resolve_instance_id(instance_id: str | None) -> str:
            assert instance_id is not None
            return instance_id

        def ensure_autoanalysis(
            self,
            _instance_id: str | None,
            *,
            operation_id: str | None = None,
        ) -> None:
            assert operation_id is not None
            self.started.set()
            assert self.release.wait(2)
            # Successful completion races with the accepted cancellation. User
            # code must still not start after the MCP request was cancelled.

        def execute_python(self, *_args, **_kwargs):
            self.executed.set()
            raise AssertionError("execution should not follow cancelled analysis")

        def cancel_operation(self, instance_id: str, operation_id: str) -> bool:
            self.cancel_calls.append((instance_id, operation_id))
            self.release.set()
            return True

    manager = BlockingManager()
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda *_args, **_kwargs: None),
    )
    result: dict[str, object] = {}

    def call() -> None:
        result["response"] = mcp_app.mcp._dispatch_mcp(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "execute_python",
                    "arguments": {
                        "code": "1",
                        "instance_id": "test-instance",
                    },
                },
                "id": "cancel-me",
            }
        )

    thread = threading.Thread(target=call, daemon=True)
    thread.start()
    assert manager.started.wait(1)
    mcp_app.mcp._dispatch_mcp(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "cancel-me", "reason": "client timeout"},
        }
    )
    thread.join(2)

    assert not thread.is_alive()
    assert result["response"] is None
    assert not manager.executed.is_set()
    assert manager.cancel_calls
    assert {instance for instance, _operation in manager.cancel_calls} == {
        "test-instance"
    }
    assert len({operation for _instance, operation in manager.cancel_calls}) == 1


def test_cancelling_queued_mcp_execution_does_not_cancel_running_request(
    monkeypatch,
) -> None:
    class QueuedManager:
        def __init__(self) -> None:
            self.operation_lock = threading.Lock()
            self.state_lock = threading.Lock()
            self.active: tuple[str, str] | None = None
            self.operation_ids: dict[str, str] = {}
            self.first_started = threading.Event()
            self.first_release = threading.Event()
            self.second_waiting = threading.Event()
            self.second_started = threading.Event()
            self.second_release = threading.Event()
            self.cancel_attempted = threading.Event()
            self.cancel_calls: list[str] = []

        @staticmethod
        def resolve_instance_id(instance_id: str | None) -> str:
            assert instance_id is not None
            return instance_id

        @staticmethod
        def ensure_autoanalysis(
            _instance_id: str,
            *,
            operation_id: str | None = None,
        ) -> None:
            assert operation_id is not None

        def execute_python(
            self,
            code: str,
            _instance_id: str,
            timeout: float | None = None,
            *,
            operation_id: str | None = None,
            operation_label: str | None = None,
            persist_globals: bool = False,
        ) -> dict[str, object]:
            assert timeout == 360
            assert persist_globals
            assert operation_id is not None
            assert operation_label == "ida-nexus mcp"
            self.operation_ids[code] = operation_id
            if code == "second":
                self.second_waiting.set()
            with self.operation_lock:
                with self.state_lock:
                    self.active = (code, operation_id)
                if code == "first":
                    self.first_started.set()
                    assert self.first_release.wait(2)
                else:
                    self.second_started.set()
                    assert self.second_release.wait(2)
                with self.state_lock:
                    self.active = None
            if code == "second":
                raise RuntimeError("second operation cancelled")
            return {"result": code, "stdout": "", "stderr": ""}

        def cancel_operation(self, _instance_id: str, operation_id: str) -> bool:
            self.cancel_calls.append(operation_id)
            self.cancel_attempted.set()
            with self.state_lock:
                active = self.active
            if active is None or active[1] != operation_id:
                return False
            if active[0] == "first":
                self.first_release.set()
            else:
                self.second_release.set()
            return True

    manager = QueuedManager()
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda *_args, **_kwargs: None),
    )
    results: dict[str, object] = {}

    def call(code: str, request_id: str) -> None:
        results[request_id] = mcp_app.mcp._dispatch_mcp(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "execute_python",
                    "arguments": {"code": code, "instance_id": "test-instance"},
                },
                "id": request_id,
            }
        )

    first = threading.Thread(target=call, args=("first", "first-request"))
    second = threading.Thread(target=call, args=("second", "second-request"))
    first.start()
    assert manager.first_started.wait(1)
    second.start()
    assert manager.second_waiting.wait(1)

    mcp_app.mcp._dispatch_mcp(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "second-request", "reason": "client timeout"},
        }
    )
    assert manager.cancel_attempted.wait(1)
    manager.first_release.set()
    assert manager.second_started.wait(1)
    first.join(2)
    second.join(2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert results["first-request"] is not None
    assert results["second-request"] is None
    assert manager.operation_ids["first"] != manager.operation_ids["second"]
    assert set(manager.cancel_calls) == {manager.operation_ids["second"]}


def test_stdio_eof_starts_shutdown_once() -> None:
    shutdown_calls: list[None] = []
    stdin = mcp_app._ShutdownOnEOFInput(
        BytesIO(b'{"jsonrpc":"2.0"}\n'),
        lambda: shutdown_calls.append(None),
    )

    assert stdin.readline() == b'{"jsonrpc":"2.0"}\n'
    assert shutdown_calls == []
    assert stdin.readline() == b""
    assert stdin.readline() == b""
    assert shutdown_calls == [None]


def test_mcp_execute_schema_exposes_numeric_timeout_default() -> None:
    tools = mcp_app.mcp.registry.methods["tools/list"]()["tools"]
    execute_tool = next(tool for tool in tools if tool["name"] == "execute_python")
    timeout_schema = execute_tool["inputSchema"]["properties"]["timeout"]

    assert timeout_schema == {
        "type": "number",
        "description": (
            "Python execution timeout in seconds. This does not include the separate "
            "initial autoanalysis wait."
        ),
        "default": 360,
    }


def test_mcp_session_fields_retain_all_request_metadata(monkeypatch) -> None:
    monkeypatch.setenv("IDA_NEXUS_ID", "trusted-nexus-id")

    assert mcp_app._session_fields_from_meta(
        {
            "dsh_session_id": "session-42",
            "future_agent_session_path": "/tmp/future-session.jsonl",
            "future_agent": {"name": "example", "version": 1},
            "enabled": False,
            "nexus_id": "untrusted-nexus-id",
        }
    ) == {
        "dsh_session_id": "session-42",
        "future_agent_session_path": "/tmp/future-session.jsonl",
        "future_agent": {"name": "example", "version": 1},
        "enabled": False,
        "nexus_id": "trusted-nexus-id",
    }


def test_mcp_trace_is_created_on_first_tool_call(tmp_path: Path, monkeypatch) -> None:
    sessions_dir = tmp_path / "sessions"
    monkeypatch.setattr(mcp_app, "SESSIONS_DIR", sessions_dir)
    trace = mcp_app._TraceLogger()

    trace.emit("mcp_started", agent="test-agent")
    trace.emit("mcp_initialized", clientInfo={"name": "test-client"})

    assert not sessions_dir.exists()
    assert not trace.path.exists()

    trace.emit("tool_call", call_id="call-1", tool="list_databases")
    trace.emit("tool_result", call_id="call-1", tool="list_databases")

    records = [json.loads(line) for line in trace.path.read_text().splitlines()]
    assert [record["event"] for record in records] == [
        "mcp_started",
        "mcp_initialized",
        "tool_call",
        "tool_result",
    ]


def test_mcp_trace_is_discarded_without_a_tool_call(
    tmp_path: Path, monkeypatch
) -> None:
    sessions_dir = tmp_path / "sessions"
    monkeypatch.setattr(mcp_app, "SESSIONS_DIR", sessions_dir)
    trace = mcp_app._TraceLogger()

    trace.emit("mcp_started", agent="test-agent")
    trace.emit("mcp_initialized", clientInfo={"name": "test-client"})
    trace.emit("mcp_stopped")

    assert not sessions_dir.exists()
    assert not trace.path.exists()


def test_mcp_session_trace_metadata(tmp_path: Path, monkeypatch) -> None:
    class FakeTrace:
        path = tmp_path / "session.jsonl"

        def __init__(self) -> None:
            self.records: list[tuple[str, dict[str, object]]] = []

        def emit(self, event: str, **fields: object) -> None:
            self.records.append((event, fields))

    trace = FakeTrace()
    manager = DatabaseManager(
        on_event=mcp_app._trace_database_event,
    )
    monkeypatch.setattr(mcp_app, "TRACE", trace)
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(mcp_app, "_TRACE_STARTED", False)
    monkeypatch.setattr(mcp_app, "_TRACE_STOPPED", False)

    mcp_app._start_mcp_trace("stdio", "test-agent")
    assert mcp_app._OPERATION_LABEL == "test-agent"
    mcp_app.mcp.registry.methods["initialize"](
        "2025-06-18",
        {},
        {"name": "test-client", "version": "1.0"},
        {"model": "test-model"},
    )
    manager._emit("database_opened", instance_id="test-instance")
    mcp_app._shutdown_server_state()

    assert [event for event, _fields in trace.records] == [
        "mcp_started",
        "mcp_initialized",
        "database_opened",
        "mcp_stopped",
    ]
    assert trace.records[0][1]["agent"] == "test-agent"
    assert trace.records[1][1]["clientInfo"] == {
        "name": "test-client",
        "version": "1.0",
    }
    assert trace.records[1][1]["_meta"] == {"model": "test-model"}
    assert trace.records[2][1]["instance_id"] == "test-instance"


def test_database_event_inherits_active_trace_call_id(monkeypatch) -> None:
    records: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda event, **fields: records.append((event, fields))),
    )

    token = mcp_app._TRACE_CALL_ID.set("tool-call-id")
    try:
        mcp_app._trace_database_event("database_opened", {"instance_id": "instance-1"})
    finally:
        mcp_app._TRACE_CALL_ID.reset(token)

    assert len(records) == 1
    event, fields = records[0]
    assert event == "database_opened"
    assert fields["instance_id"] == "instance-1"
    assert fields["call_id"] == "tool-call-id"


def test_database_disconnect_sends_structured_warning(monkeypatch) -> None:
    traces: list[tuple[str, dict[str, object]]] = []
    output = BytesIO()
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda event, **fields: traces.append((event, fields))),
    )
    database_state = {
        "state": "crashed",
        "id0_path": "/tmp/sample.id0",
        "packed_database_exists": False,
    }
    target = {
        "record_id": "123-deadbe",
        "pid": 123,
        "idb_path": "/tmp/sample.i64",
        "worker_log_path": "/tmp/123-deadbe.log",
    }

    with mcp_app.mcp._stdio_output_scope(output):
        mcp_app._trace_database_event(
            "database_disconnected",
            {
                "instance_id": "instance-1",
                "reason": "database process crashed",
                "target": target,
                "database_state": database_state,
            },
        )

    notification = json.loads(output.getvalue())
    assert notification["method"] == "notifications/message"
    assert notification["params"] == {
        "level": "warning",
        "logger": "ida_nexus.database",
        "data": {
            "event": "database_lost",
            "message": (
                "IDA database worker crashed; "
                "the previous instance is permanently invalid"
            ),
            "instance_id": "instance-1",
            "reason": "database process crashed",
            "target": target,
            "database_state": database_state,
            "recovery_required": True,
        },
    }
    assert traces[0][0] == "database_disconnected"
    assert traces[0][1]["level"] == "warning"
    assert traces[0][1]["database_state"] == database_state


def test_database_disconnect_trace_survives_unavailable_logging_transport(
    monkeypatch,
) -> None:
    traces: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda event, **fields: traces.append((event, fields))),
    )

    def unavailable(*_args, **_kwargs) -> None:
        raise RuntimeError("no active stdio transport")

    monkeypatch.setattr(mcp_app.mcp, "send_log_message", unavailable)

    mcp_app._trace_database_event(
        "database_disconnected",
        {
            "instance_id": "instance-1",
            "reason": "connection closed",
            "database_state": {"state": "unknown"},
        },
    )

    assert traces[0][0] == "database_disconnected"
    assert traces[0][1]["level"] == "warning"


def test_list_databases_does_not_wait_for_an_active_operation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class BlockingBackend(StaticBackend):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

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
            flush_database: bool = False,
        ) -> PythonExecutionResult:
            self.started.set()
            assert self.release.wait(2)
            return super().execute_python(
                code,
                timeout,
                lease_id=lease_id,
                operation_id=operation_id,
                operation_label=operation_label,
                persist_globals=persist_globals,
                filename=filename,
                flush_database=flush_database,
            )

    idb_path = tmp_path / "open.i64"
    idb_path.write_bytes(b"idb")
    backend = BlockingBackend()
    server = NexusHTTPServer(
        backend,
        InstanceIdentity(str(idb_path), "", "gui"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(idb_path), set_current=True)
    execution_errors: list[Exception] = []

    def execute_python() -> None:
        try:
            manager.execute_python("1", opened["instance_id"], timeout=2)
        except Exception as error:  # noqa: BLE001 - asserted below
            execution_errors.append(error)

    execution = threading.Thread(target=execute_python, daemon=True)
    execution.start()
    assert backend.started.wait(1)
    monkeypatch.setattr("ida_nexus.manager.scan_instances", list)

    listing_finished = threading.Event()
    errors: list[Exception] = []

    def list_databases() -> None:
        try:
            manager.list_databases()
        except Exception as error:  # noqa: BLE001 - asserted below
            errors.append(error)
        finally:
            listing_finished.set()

    thread = threading.Thread(target=list_databases, daemon=True)
    thread.start()
    try:
        completed_while_operation_was_active = listing_finished.wait(0.25)
    finally:
        backend.release.set()
        execution.join(2)
        thread.join(2)
        manager.shutdown()
        server.stop()
        server.release_registration()

    assert not execution.is_alive()
    assert execution_errors == []
    assert errors == []
    assert completed_while_operation_was_active


def test_list_databases_uses_idb_when_gui_executable_is_missing(tmp_path: Path) -> None:
    registry_dir = REGISTRY_DIR
    idb_path = tmp_path / "open.i64"
    idb_path.write_bytes(b"idb")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(tmp_path / "missing.exe"), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    entry = server.entry
    try:
        result = DatabaseManager().list_databases()
    finally:
        server.stop()
        server.release_registration()

    assert result == {
        "instances": [
            {
                "path": entry.idb_path,
                "backend": "gui",
                "status": "available",
                "instance_id": None,
                "error": None,
            }
        ]
    }


def test_list_databases_prefers_existing_gui_executable(tmp_path: Path) -> None:
    registry_dir = REGISTRY_DIR
    idb_path = tmp_path / "open.i64"
    executable = tmp_path / "open.exe"
    idb_path.write_bytes(b"idb")
    executable.write_bytes(b"binary")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    try:
        result = DatabaseManager().list_databases()
    finally:
        server.stop()
        server.release_registration()

    assert result["instances"][0]["path"] == canonical_path(executable)


def test_paths_preserve_case_but_matching_is_case_insensitive(tmp_path: Path) -> None:
    # Regression: real paths must keep their on-disk case (so IDBs are created
    # exactly as IDA would name them, not lowercased), while discovery matching
    # stays case-insensitive on macOS/Windows and works for either the
    # executable or the .i64 path.
    import sys

    from ida_nexus._resolver import expected_idb_path, resolve_instance

    idb_path = tmp_path / "MixedCase.exe.i64"
    executable = tmp_path / "MixedCase.exe"
    idb_path.write_bytes(b"idb")
    executable.write_bytes(b"binary")

    # Real paths keep case; the fold lives only in the identity key.
    assert canonical_path(executable).endswith("MixedCase.exe")
    assert expected_idb_path(executable).endswith("MixedCase.exe.i64")

    registry_dir = REGISTRY_DIR
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    try:
        # The listed path preserves case (no more lowercase databases).
        result = DatabaseManager().list_databases()
        assert result["instances"][0]["path"].endswith("MixedCase.exe")

        # The model may pass the executable or the .i64; both find the one
        # instance without spawning a worker.
        variants = [executable, idb_path]
        if sys.platform in ("darwin", "win32"):
            # Case-insensitive volumes: differently-cased spellings name the
            # same file and must resolve to the same instance.
            variants += [tmp_path / "mixedcase.exe", tmp_path / "mixedcase.exe.i64"]
        record_ids = {resolve_instance(str(p), spawn=False).record_id for p in variants}
        assert record_ids == {server.entry.record_id}
    finally:
        server.stop()
        server.release_registration()


def test_resolves_live_instance_when_idb_not_on_disk(tmp_path: Path) -> None:
    # Regression: a freshly-opened GUI database has no .i64 on disk until it is
    # saved. Attaching to that live instance must work via either the .i64 path
    # (which does not exist yet) or the executable path, without a premature
    # "database path does not exist" rejection.
    from ida_nexus._resolver import resolve_instance

    executable = tmp_path / "Fresh.exe"
    executable.write_bytes(b"binary")
    idb_path = tmp_path / "Fresh.exe.i64"  # intentionally NOT created on disk
    assert not idb_path.exists()

    registry_dir = REGISTRY_DIR
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    try:
        for lookup in (idb_path, executable):
            entry = resolve_instance(str(lookup), spawn=False)
            assert entry.record_id == server.entry.record_id
    finally:
        server.stop()
        server.release_registration()


def test_get_session_waits_for_in_flight_startup_open(tmp_path: Path) -> None:
    # Regression: the agent's first tool call must not race a --database startup
    # open. _get_session waits for the background thread to finish attaching.
    manager = DatabaseManager()
    sentinel: Any = object()

    def _startup() -> None:
        time.sleep(0.2)  # attach lands after the first tool call arrives
        with manager._lock:
            manager._instances["inst-1"] = sentinel
            manager._current_instance_id = "inst-1"

    thread = threading.Thread(target=_startup, daemon=True)
    manager._startup_open_thread = thread
    thread.start()

    # A naive lookup would fail here; _get_session must block on the thread.
    target_id, session = manager._get_session(None)
    assert target_id == "inst-1"
    assert session is sentinel


def test_shutdown_during_open_releases_the_late_handle(monkeypatch) -> None:
    open_started = threading.Event()
    finish_open = threading.Event()
    handle_closed = threading.Event()
    failures: list[Exception] = []

    entry = DatabaseInstance(
        record_id="123-abcdef",
        backend="gui",
        pid=123,
        port=12345,
        _token="token",
        version=1,
        idb_path="/tmp/test.i64",
        idb_key="test-key",
        exe_path="/tmp/test",
        managed=False,
        started_at=0.0,
    )

    class SlowHandle:
        def __init__(self) -> None:
            self.instance = entry
            self.disconnect_reason = None
            self._connected = True

        @property
        def connected(self) -> bool:
            return self._connected

        def set_disconnect_callback(self, _callback) -> None:
            pass

        def close(self) -> None:
            self._connected = False
            handle_closed.set()

    @classmethod
    def slow_open(cls, path: str, **kwargs) -> SlowHandle:
        assert path.endswith("/tmp/test")
        assert kwargs["options"].auto_analysis is True
        open_started.set()
        assert finish_open.wait(2)
        return SlowHandle()

    monkeypatch.setattr(DatabaseHandle, "open", slow_open)
    manager = DatabaseManager()

    def open_database() -> None:
        try:
            manager.open_database("/tmp/test", set_current=True)
        except Exception as exc:  # noqa: BLE001 - captured for the assertion
            failures.append(exc)

    thread = threading.Thread(target=open_database)
    thread.start()
    assert open_started.wait(1)

    # Reproduction: shutdown completes while handle creation is still blocked.
    manager.shutdown()
    finish_open.set()
    thread.join(2)

    assert not thread.is_alive()
    assert handle_closed.is_set()
    assert len(failures) == 1
    assert isinstance(failures[0], DatabaseSelectionError)
    assert "shutting down" in str(failures[0])
    assert manager._instances == {}


def test_get_session_raises_without_startup_open(tmp_path: Path) -> None:
    manager = DatabaseManager()
    try:
        manager._get_session(None)
    except DatabaseSelectionError as exc:
        assert "no open database instance" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected DatabaseSelectionError")


def test_get_session_raises_after_failed_startup_open(tmp_path: Path) -> None:
    # A startup open that finishes without setting a current DB (i.e. it failed)
    # must not hang the tool call: waiting ends when the thread ends.
    manager = DatabaseManager()
    thread = threading.Thread(target=lambda: None, daemon=True)
    manager._startup_open_thread = thread
    thread.start()
    try:
        manager._get_session(None)
    except DatabaseSelectionError as exc:
        assert "no open database instance" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected DatabaseSelectionError")


def test_mcp_execution_waits_for_autoanalysis_once_per_database(
    tmp_path: Path,
) -> None:
    class RecordingBackend(StaticBackend):
        def __init__(self, analysis: AnalysisState) -> None:
            self.analysis = analysis
            self.calls: list[tuple[object, ...]] = []

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
            flush_database: bool = False,
        ):
            self.calls.append(("execute", code, timeout, operation_id, operation_label))
            return super().execute_python(
                code,
                timeout,
                lease_id=lease_id,
                operation_id=operation_id,
                operation_label=operation_label,
                persist_globals=persist_globals,
                flush_database=flush_database,
            )

        def wait_autoanalysis(self, timeout: float | None):
            self.calls.append(("wait", timeout))
            self.analysis.mark_complete()
            return self.analysis.snapshot()

    executable = tmp_path / "sample.exe"
    idb_path = tmp_path / "sample.i64"
    executable.write_bytes(b"binary")
    idb_path.write_bytes(b"idb")
    analysis = AnalysisState()
    backend = RecordingBackend(analysis)
    server = NexusHTTPServer(
        backend,
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        analysis,
        REGISTRY_DIR,
    )
    server.start()
    manager = DatabaseManager(
        execute_timeout=7,
    )
    try:
        opened = manager.open_database(str(executable), set_current=True)

        manager.ensure_autoanalysis(opened["instance_id"])
        assert manager.execute_python("lambda: 1", opened["instance_id"]) == {
            "result": {"code": "lambda: 1", "timeout": 7.0},
            "stdout": "",
            "stderr": "",
        }
        manager.ensure_autoanalysis(opened["instance_id"])
        assert manager.execute_python("lambda: 2", opened["instance_id"], 9) == {
            "result": {"code": "lambda: 2", "timeout": 9.0},
            "stdout": "",
            "stderr": "",
        }
        assert backend.calls[0] == ("wait", None)
        first_operation = backend.calls[1]
        second_operation = backend.calls[2]
        assert first_operation[:3] == ("execute", "lambda: 1", 7.0)
        assert second_operation[:3] == ("execute", "lambda: 2", 9.0)
        first_operation_id = first_operation[3]
        second_operation_id = second_operation[3]
        assert isinstance(first_operation_id, str) and len(first_operation_id) == 32
        assert isinstance(second_operation_id, str) and len(second_operation_id) == 32
        assert first_operation_id != second_operation_id
        assert first_operation[4] is None
        assert second_operation[4] is None
    finally:
        manager.shutdown()
        server.stop()
        server.release_registration()


def test_gui_disconnect_invalidates_mcp_instance_without_spawning(
    tmp_path: Path,
) -> None:
    registry_dir = REGISTRY_DIR
    idb_path = tmp_path / "open.i64"
    executable = tmp_path / "open.exe"
    idb_path.write_bytes(b"idb")
    executable.write_bytes(b"binary")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(executable), set_current=True)

    server.stop()
    server.release_registration()
    deadline = time.monotonic() + 2
    while manager.list_databases()["instances"] and time.monotonic() < deadline:
        time.sleep(0.01)

    assert manager.list_databases() == {"instances": []}
    try:
        manager.execute_python("lambda: 1", opened["instance_id"])
    except DatabaseSelectionError as exc:
        assert "disconnected since it was last used" in str(exc)
    else:
        raise AssertionError("disconnected instance remained executable")
    assert not list(registry_dir.glob("*.json"))
    manager.shutdown()


def test_database_handle_reuses_http11_rpc_connection(tmp_path: Path) -> None:
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle("/tmp/test", server.entry)
    try:
        first = handle.execute_python("lambda: 1", 1)
        assert first["result"] == {"code": "lambda: 1", "timeout": 1}
        connection = handle._rpc_connection
        assert connection is not None
        sock = connection.sock
        assert sock is not None

        second = handle.execute_python("lambda: 2", 1)
        assert second["result"] == {"code": "lambda: 2", "timeout": 1}
        assert handle._rpc_connection is connection
        assert connection.sock is sock
        assert RequestHandler.disable_nagle_algorithm is True
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_windows_console_launcher_can_exit_before_worker_child() -> None:
    assert resolver_mod._launcher_exit_is_fatal(0, "nt") is False
    assert resolver_mod._launcher_exit_is_fatal(1, "nt") is True
    assert resolver_mod._launcher_exit_is_fatal(0, "posix") is True


def test_worker_uses_primary_idausr_entry_for_idapro(
    tmp_path: Path, monkeypatch
) -> None:
    primary = tmp_path / "primary"
    secondary = tmp_path / "secondary"
    monkeypatch.setenv("IDAUSR", f"{primary}{os.pathsep}{secondary}")

    _work_around_idapro_idausr_path_list()

    assert os.environ["IDAUSR"] == str(primary)


def test_image_base_uses_byte_units_and_requires_paragraph_alignment() -> None:
    assert _parse_image_base("0x8000") == 0x8000
    assert _image_base_to_paragraphs(0x8000) == 0x800
    assert _image_base_to_paragraphs(None) is None
    parsed = worker_parser().parse_args(["input.bin", "--debug-mask", "0x80"])
    assert _build_ida_options(parsed, lambda **kwargs: kwargs)["debug_flags"] == 0x80
    for value in ("-1", "0x8001", "not-an-address"):
        try:
            _parse_image_base(value)
        except argparse.ArgumentTypeError:
            pass
        else:
            raise AssertionError(f"invalid image base accepted: {value}")
    try:
        resolver_mod.WorkerLaunchOptions(image_base=0x8001)
    except ValueError as exc:
        assert "16-byte aligned" in str(exc)
    else:
        raise AssertionError("unaligned API image base accepted")


def test_fresh_worker_opens_source_instead_of_existing_idb(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    expected_idb = tmp_path / "sample.exe.i64"
    source.write_bytes(b"binary")
    expected_idb.write_bytes(b"old idb")

    command = resolver_mod._build_worker_command(
        str(source),
        str(expected_idb),
        20.0,
        resolver_mod.WorkerLaunchOptions(
            image_base=0x8000,
            new_database=True,
        ),
        launcher=["ida-nexus", "worker"],
        record_suffix="abcdef",
    )

    assert command[:3] == ["ida-nexus", "worker", str(source)]
    assert command[command.index("--output-database") + 1] == str(expected_idb)
    assert command[command.index("--image-base") + 1] == "0x8000"
    assert "--new-database" in command


def test_existing_idb_drops_source_import_options(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    expected_idb = tmp_path / "firmware.bin.i64"
    source.write_bytes(b"binary")
    expected_idb.write_bytes(b"database")

    command = resolver_mod._build_worker_command(
        str(source),
        str(expected_idb),
        7.5,
        resolver_mod.WorkerLaunchOptions(
            auto_analysis=True,
            image_base=0x8000,
            processor="arm",
            file_type="Raw",
        ),
        launcher=["ida-nexus", "worker"],
        record_suffix="abcdef",
    )

    assert command[:3] == ["ida-nexus", "worker", str(expected_idb)]
    assert "--auto-analysis" in command
    assert "--image-base" not in command
    assert "--processor" not in command
    assert "--file-type" not in command


def test_worker_launch_forwards_all_ida_command_options(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    expected_idb = tmp_path / "firmware.i64"
    source.write_bytes(b"binary")
    log_file = tmp_path / "ida kernel.log"
    script_file = tmp_path / "startup.py"
    windows_dir = tmp_path / "windows"

    command = resolver_mod._build_worker_command(
        str(source),
        str(expected_idb),
        7.5,
        resolver_mod.WorkerLaunchOptions(
            auto_analysis=True,
            image_base=0x8000,
            new_database=True,
            compiler="gcc:sysv",
            first_pass_directives=("FIRST=1", "FIRST=2"),
            second_pass_directives=("SECOND=1",),
            disable_fpp=True,
            entry_point=0x8010,
            jit_debugger=False,
            log_file=str(log_file),
            disable_mouse=True,
            plugin_options="sample:option",
            processor="arm",
            db_compression="compress",
            run_debugger="linux",
            load_resources=True,
            script_file=str(script_file),
            script_args=("--flag", "argument two"),
            file_type="ZIP",
            file_member="nested.bin",
            empty_database=True,
            windows_dir=str(windows_dir),
            no_segmentation=True,
            debug_flags=("ldr", "debugger"),
        ),
        launcher=["ida-nexus", "worker"],
        record_suffix="abcdef",
    )

    assert command[:2] == ["ida-nexus", "worker"]
    assert "--auto-analysis" in command
    assert command[command.index("--image-base") + 1] == "0x8000"
    assert "--new-database" in command
    assert "--compiler=gcc:sysv" in command
    assert "--first-pass-directive=FIRST=1" in command
    assert "--first-pass-directive=FIRST=2" in command
    assert "--second-pass-directive=SECOND=1" in command
    assert "--disable-fpp" in command
    assert command[command.index("--entry-point") + 1] == "0x8010"
    assert "--no-jit-debugger" in command
    assert command[command.index("--log-file") + 1] == str(log_file)
    assert "--disable-mouse" in command
    assert "--plugin-options=sample:option" in command
    assert command[command.index("--processor") + 1] == "arm"
    assert command[command.index("--db-compression") + 1] == "compress"
    assert "--run-debugger=linux" in command
    assert "--load-resources" in command
    assert command[command.index("--script-file") + 1] == str(script_file)
    assert "--script-arg=--flag" in command
    assert "--script-arg=argument two" in command
    assert command[command.index("--file-type") + 1] == "ZIP"
    assert command[command.index("--file-member") + 1] == "nested.bin"
    assert "--empty-database" in command
    assert command[command.index("--windows-dir") + 1] == str(windows_dir)
    assert "--no-segmentation" in command
    assert "--debug-flag=ldr" in command
    assert "--debug-flag=debugger" in command

    parsed = worker_parser().parse_args(command[2:])
    ida_options = _build_ida_options(parsed, lambda **kwargs: kwargs)
    assert ida_options == {
        # The worker publishes before starting analysis through Nexus.
        "auto_analysis": False,
        "loading_address": 0x800,
        "new_database": True,
        "compiler": "gcc:sysv",
        "first_pass_directives": ["FIRST=1", "FIRST=2"],
        "second_pass_directives": ["SECOND=1"],
        "disable_fpp": True,
        "entry_point": 0x8010,
        "jit_debugger": False,
        "log_file": str(log_file.resolve()),
        "disable_mouse": True,
        "plugin_options": "sample:option",
        "output_database": str(expected_idb.resolve()),
        "processor": "arm",
        "db_compression": "compress",
        "run_debugger": "linux",
        "load_resources": True,
        "script_file": str(script_file.resolve()),
        "script_args": ["--flag", "argument two"],
        "file_type": "ZIP",
        "file_member": "nested.bin",
        "empty_database": True,
        "windows_dir": str(windows_dir.resolve()),
        "no_segmentation": True,
        "debug_flags": ["ldr", "debugger"],
    }


def test_await_ready_accepts_console_launcher_child_pid(tmp_path: Path) -> None:
    expected_idb = str(tmp_path / "sample.i64")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(expected_idb, str(tmp_path / "sample"), "idalib"),
        AnalysisState(),
        REGISTRY_DIR,
        record_suffix="abcdef",
    )
    server.start()
    assert server.entry is not None
    entry = server.entry
    process = cast(subprocess.Popen[bytes], SimpleNamespace(pid=111, poll=lambda: None))
    try:
        result = resolver_mod._await_ready(
            process,
            expected_idb,
            tmp_path / "111-abcdef.log",
            time.monotonic() + 1,
        )
    finally:
        server.stop()
        server.release_registration()

    assert result == entry


def test_database_handle_attach_and_poll_use_exact_entry(tmp_path: Path) -> None:
    analysis = AnalysisState()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        analysis,
        REGISTRY_DIR,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry)
    try:
        assert handle.path == server.entry.exe_path
        assert handle.instance.record_id == server.entry.record_id
        assert handle.poll_autoanalysis() == {
            "status": "running",
            "complete": False,
        }
        analysis.mark_complete()
        assert handle.poll_autoanalysis() == {
            "status": "complete",
            "complete": True,
        }
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_database_handle_exposes_closeable_idb_event_iterator(tmp_path: Path) -> None:
    analysis = AnalysisState()
    backend = StaticBackend()
    server = NexusHTTPServer(
        backend,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        analysis,
        REGISTRY_DIR,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry)
    try:
        with handle.subscribe_idb_events() as events:
            assert events in handle._idb_subscriptions
            analysis.mark_complete()
            assert server._idb_event_hook_enabled
            backend.record_idb_change(
                "first",
                "first label",
                handle.event_origin_id,
            )
            event = next(events)
            assert event == {
                "event_name": "first",
                "timestamp": 1,
                "revision": 1,
                "operation_id": "first",
                "operation_label": "first label",
                "origin_id": handle.event_origin_id,
            }
            assert handle.owns_event(event)
            assert not handle.owns_event({**event, "origin_id": "another-handle"})
            assert len(handle.event_origin_id) == 32
        assert events.closed
        assert events not in handle._idb_subscriptions
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_database_handle_closes_idb_event_iterators(tmp_path: Path) -> None:
    analysis = AnalysisState()
    analysis.mark_complete()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        analysis,
        REGISTRY_DIR,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry)
    events = handle.subscribe_idb_events()
    stopped = threading.Event()

    def read_event() -> None:
        try:
            next(events)
        except StopIteration:
            stopped.set()

    reader = threading.Thread(target=read_event, daemon=True)
    reader.start()
    try:
        time.sleep(0.05)
        handle.close()
        assert events.closed
        assert stopped.wait(1)
        reader.join(timeout=1)
        assert not reader.is_alive()
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_public_idb_event_subscription_closes_with_handle(tmp_path: Path) -> None:
    analysis = AnalysisState()
    analysis.mark_complete()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        analysis,
        REGISTRY_DIR,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry)
    events = DatabaseChangeSubscription(handle)
    try:
        assert events in handle._idb_subscriptions
        handle.close()
        assert events.closed
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_idb_event_iterator_reports_handle_disconnect(tmp_path: Path) -> None:
    analysis = AnalysisState()
    analysis.mark_complete()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        analysis,
        REGISTRY_DIR,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry)
    events = handle.subscribe_idb_events()
    errors: list[DatabaseDisconnectedError] = []

    def read_event() -> None:
        try:
            next(events)
        except DatabaseDisconnectedError as exc:
            errors.append(exc)

    reader = threading.Thread(target=read_event, daemon=True)
    reader.start()
    try:
        time.sleep(0.05)
        handle._mark_disconnected("database connection lost")
        reader.join(timeout=1)
        assert not reader.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], DatabaseDisconnectedError)
        assert str(errors[0]) == "database connection lost"
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_multiple_leases_share_one_managed_server(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=0.1,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    first = DatabaseHandle("/tmp/test", server.entry)
    second = DatabaseHandle("/tmp/test", server.entry)
    try:
        first.close()
        time.sleep(0.15)
        assert not stopped.is_set()
        assert second.execute_python("lambda: 1", 1) == {
            "result": {"code": "lambda: 1", "timeout": 1.0},
            "stdout": "",
            "stderr": "",
        }
        assert second.wait_autoanalysis(1) == {
            "status": "complete",
            "complete": True,
        }
    finally:
        second.close()
    assert stopped.wait(2)
    server.release_registration()


def test_exclusive_managed_worker_can_shutdown_without_saving(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry)
    try:
        assert handle.shutdown_database(save=False) == {
            "shutting_down": True,
            "save": False,
        }
        assert stopped.wait(2)
        assert server.save_on_shutdown is False
    finally:
        handle.close()
        server.release_registration()


def test_managed_worker_shutdown_rejects_another_lease(tmp_path: Path) -> None:
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    first = DatabaseHandle.attach(server.entry)
    second = DatabaseHandle.attach(server.entry)
    try:
        try:
            first.shutdown_database(save=False)
        except client_mod.RemoteError as exc:
            assert exc.code == "instance_shared"
        else:  # pragma: no cover
            raise AssertionError("shared worker accepted exclusive shutdown")
    finally:
        first.close()
        second.close()
        server.release_registration()


def test_final_explicit_release_skips_startup_grace(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=30,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle("/tmp/test", server.entry)
    handle.close()
    assert stopped.wait(1)
    server.release_registration()


def test_draining_owner_remains_discoverable_until_database_close(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.exe.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"database")
    stopped = threading.Event()
    registry_dir = REGISTRY_DIR
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        registry_dir,
        lease_grace=30,
        heartbeat_interval=30,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    record_path = registry_dir / f"{server.entry.record_id}.json"
    handle = DatabaseHandle(str(executable), server.entry)
    handle.close()
    assert stopped.wait(1)

    discovered = scan_instances(registry_dir)
    assert len(discovered) == 1
    assert discovered[0].state is InstanceState.BLOCKED
    assert record_path.is_file()
    assert server._registration is not None
    assert server._registration.lock._locked

    spawned = False

    def unexpected_spawner(*_args: Any):
        nonlocal spawned
        spawned = True
        raise AssertionError("spawned over a draining IDB owner")

    try:
        resolve_instance(
            executable,
            timeout=1,
            spawner=unexpected_spawner,
        )
    except resolver_mod.DatabaseBusyError:
        pass
    else:
        raise AssertionError("draining owner was not reported as busy")
    assert not spawned

    # The lifecycle owner calls this only after database.close()/unhook().
    server.release_registration()
    assert not record_path.exists()


def test_handle_idle_timeout_disconnects_only_managed_workers(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    reasons: list[str] = []
    handle = DatabaseHandle.attach(
        server.entry,
        idle_timeout=0.1,
        on_disconnect=lambda _handle, reason: reasons.append(reason),
    )
    try:
        deadline = time.monotonic() + 1
        while handle.connected and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not handle.connected
        assert reasons == ["database lease expired after 0.1 seconds of inactivity"]
        assert stopped.wait(1)
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_handle_idle_timeout_is_ignored_for_gui(tmp_path: Path) -> None:
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        REGISTRY_DIR,
        heartbeat_interval=0.02,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle.attach(server.entry, idle_timeout=0.05)
    try:
        time.sleep(0.1)
        assert handle.connected
        assert handle.idle_timeout is None
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_handle_keepalive_retains_idle_managed_worker(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle("/tmp/test", server.entry, keepalive=0.25)
    handle.close()
    assert not stopped.wait(0.1)
    assert server.entry is not None
    replacement = DatabaseHandle("/tmp/test", server.entry, keepalive=0.1)
    replacement.close()
    assert not stopped.wait(0.05)
    assert stopped.wait(1)
    server.release_registration()


def test_operation_cancellation_cannot_reach_successor(tmp_path: Path) -> None:
    class HandoffBackend(StaticBackend):
        def __init__(self) -> None:
            self.current: str | None = None
            self.first_started = threading.Event()
            self.first_release = threading.Event()
            self.second_started = threading.Event()
            self.second_release = threading.Event()
            self.cancel_entered = threading.Event()
            self.cancel_release = threading.Event()
            self.cancelled_target: str | None = None

        def cancel_active(self) -> None:
            self.cancel_entered.set()
            assert self.cancel_release.wait(2)
            self.cancelled_target = self.current

    backend = HandoffBackend()
    server = NexusHTTPServer(
        backend,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    assert server._lease_opened("test-lease", 0) is not None
    failures: list[BaseException] = []

    def run(operation_id: str, operation) -> None:
        try:
            server._run_operation("test-lease", operation, operation_id)
        except BaseException as error:  # noqa: BLE001 - collected for the assertion
            failures.append(error)

    def first_operation() -> None:
        backend.current = "first"
        backend.first_started.set()
        assert backend.first_release.wait(2)
        backend.current = None

    def second_operation() -> None:
        backend.current = "second"
        backend.second_started.set()
        assert backend.second_release.wait(2)
        backend.current = None

    first = threading.Thread(target=run, args=("first", first_operation))
    second = threading.Thread(target=run, args=("second", second_operation))
    cancel = threading.Thread(
        target=lambda: server._cancel_operation("test-lease", "first")
    )
    first.start()
    assert backend.first_started.wait(1)
    second.start()
    cancel.start()
    assert backend.cancel_entered.wait(1)

    backend.first_release.set()
    # cancel_active() still owns the handoff barrier, so the successor cannot
    # become the backend's active generation until cancellation returns.
    assert not backend.second_started.wait(0.1)
    backend.cancel_release.set()
    assert backend.second_started.wait(1)
    backend.second_release.set()

    first.join(2)
    second.join(2)
    cancel.join(2)
    assert not first.is_alive() and not second.is_alive() and not cancel.is_alive()
    assert failures == []
    assert backend.cancelled_target != "second"
    server._lease_closed("test-lease")


def test_cancel_active_preserves_database_handle(tmp_path: Path) -> None:
    class CancellableBackend(StaticBackend):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.cancelled = threading.Event()

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
            flush_database: bool = False,
        ):
            if code == "second":
                return super().execute_python(
                    code,
                    timeout,
                    lease_id=lease_id,
                    operation_id=operation_id,
                    operation_label=operation_label,
                    persist_globals=persist_globals,
                    flush_database=flush_database,
                )
            self.started.set()
            assert self.cancelled.wait(2)
            raise RuntimeError("cancelled")

        def cancel_active(self) -> None:
            self.cancelled.set()

    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    backend = CancellableBackend()
    server = NexusHTTPServer(
        backend,
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        on_shutdown=lambda: server.release_registration(),
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(idb), set_current=True)
    failures: list[Exception] = []

    def execute() -> None:
        try:
            manager.execute_python("first", opened["instance_id"])
        except Exception as exc:  # noqa: BLE001 - asserted below
            failures.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert backend.started.wait(1)
    assert manager.cancel_active(opened["instance_id"]) is True
    thread.join(2)

    assert not thread.is_alive()
    assert failures
    assert manager.execute_python("second", opened["instance_id"], 1) == {
        "result": {"code": "second", "timeout": 1.0},
        "stdout": "",
        "stderr": "",
    }
    manager.shutdown()
    server.stop()
    server.release_registration()


def test_manager_close_waits_for_final_managed_idb_close(tmp_path: Path) -> None:
    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    shutdown_started = threading.Event()
    idb_closed = threading.Event()

    def finish_shutdown() -> None:
        shutdown_started.set()
        assert idb_closed.wait(2)
        server.release_registration()

    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        on_shutdown=finish_shutdown,
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(idb), set_current=True)
    failures: list[Exception] = []

    def close_database() -> None:
        try:
            manager.close_database(opened["instance_id"])
        except Exception as exc:  # noqa: BLE001 - asserted below
            failures.append(exc)

    thread = threading.Thread(target=close_database)
    thread.start()
    assert shutdown_started.wait(1)
    assert thread.is_alive()
    idb_closed.set()
    thread.join(2)

    assert not thread.is_alive()
    assert failures == []
    server.stop()
    server.release_registration()


def test_manager_shutdown_waits_for_final_managed_idb_close(tmp_path: Path) -> None:
    # Regression: process shutdown must drain the worker's final pack. Returning
    # while the IDB is still being written leaves a stale or truncated .i64
    # behind when whatever stops this process also kills the worker.
    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    shutdown_started = threading.Event()
    idb_closed = threading.Event()

    def finish_shutdown() -> None:
        shutdown_started.set()
        assert idb_closed.wait(2)
        server.release_registration()

    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        on_shutdown=finish_shutdown,
    )
    server.start()
    events: list[tuple[str, dict[str, Any]]] = []
    manager = DatabaseManager(
        on_event=lambda event, fields: events.append((event, fields))
    )
    manager.open_database(str(idb), set_current=True)

    thread = threading.Thread(target=manager.shutdown)
    thread.start()
    assert shutdown_started.wait(1)
    assert thread.is_alive()
    idb_closed.set()
    thread.join(2)

    assert not thread.is_alive()
    assert [event for event, _fields in events] == ["database_opened"]
    server.stop()
    server.release_registration()


def test_manager_shutdown_drains_databases_concurrently(tmp_path: Path) -> None:
    # Each worker packs its own IDB, so both releases must be in flight at once.
    # A serial drain could not reach the second worker while the first one is
    # still packing, which is how the last database would lose its pack.
    release = threading.Event()
    servers: dict[str, NexusHTTPServer] = {}
    packing = {name: threading.Event() for name in ("first", "second")}

    def start_worker(name: str) -> None:
        idb = tmp_path / f"{name}.i64"
        executable = tmp_path / f"{name}.exe"
        idb.write_bytes(b"idb")
        executable.write_bytes(b"binary")

        def on_shutdown() -> None:
            packing[name].set()
            assert release.wait(3)
            servers[name].release_registration()

        servers[name] = NexusHTTPServer(
            StaticBackend(),
            InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
            AnalysisState(),
            REGISTRY_DIR,
            lease_grace=30,
            on_shutdown=on_shutdown,
        )
        servers[name].start()

    events: list[tuple[str, dict[str, Any]]] = []
    manager = DatabaseManager(
        on_event=lambda event, fields: events.append((event, fields))
    )
    for name in packing:
        start_worker(name)
        manager.open_database(str(tmp_path / f"{name}.i64"), set_current=True)

    thread = threading.Thread(target=manager.shutdown)
    thread.start()
    assert packing["first"].wait(2)
    assert packing["second"].wait(2)
    assert thread.is_alive()
    release.set()
    thread.join(3)

    assert not thread.is_alive()
    assert [event for event, _fields in events] == [
        "database_opened",
        "database_opened",
    ]
    for server in servers.values():
        server.stop()
        server.release_registration()


def test_manager_shutdown_reports_a_wedged_final_idb_close(tmp_path: Path) -> None:
    # A worker that never finishes its pack must not hold up process exit; the
    # bounded wait reports the timeout and abandons it.
    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        # The worker accepts the release but never releases its lifetime lock.
        on_shutdown=lambda: None,
    )
    server.start()
    events: list[tuple[str, dict[str, Any]]] = []
    manager = DatabaseManager(
        on_event=lambda event, fields: events.append((event, fields))
    )
    opened = manager.open_database(str(idb), set_current=True)

    started = time.monotonic()
    manager.shutdown(timeout=0.25)

    assert time.monotonic() - started < 2
    assert [event for event, _fields in events] == [
        "database_opened",
        "database_release_error",
    ]
    fields = events[-1][1]
    assert fields["instance_id"] == opened["instance_id"]
    assert isinstance(fields["error"], NexusConnectionError)
    assert "waiting for the IDB to close" in str(fields["error"])
    assert manager._instances == {}
    server.stop()
    server.release_registration()


def test_database_close_cancels_its_active_execution(tmp_path: Path) -> None:
    class BlockingBackend(StaticBackend):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.cancelled = threading.Event()

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
            flush_database: bool = False,
        ):
            del lease_id, operation_id, operation_label, persist_globals, flush_database
            self.started.set()
            assert self.cancelled.wait(2)
            raise RuntimeError("cancelled")

        def cancel_active(self) -> None:
            self.cancelled.set()

    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    backend = BlockingBackend()
    server = NexusHTTPServer(
        backend,
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        # Model the worker's lifetime-lock release after its IDB closes.
        on_shutdown=lambda: server.release_registration(),
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(idb), set_current=True)
    failures: list[Exception] = []

    def execute() -> None:
        try:
            manager.execute_python("while True: pass", opened["instance_id"])
        except Exception as exc:  # noqa: BLE001 - asserted below
            failures.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert backend.started.wait(1)
    started = time.monotonic()
    manager.close_database(opened["instance_id"])
    assert time.monotonic() - started < 1
    assert backend.cancelled.wait(1)
    thread.join(2)
    assert not thread.is_alive()
    assert failures
    server.stop()
    server.release_registration()
