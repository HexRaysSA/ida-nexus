"""Manager contracts: selection, permanent failure, and races at handle boundaries."""

import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

import pytest
from test_database_state import write_id0
from test_instance_management import StaticBackend

from ida_nexus import (
    DatabaseCrashedError,
    DatabaseHandle,
    DatabaseManager,
    DatabaseSelectionError,
    NexusConnectionError,
)
from ida_nexus._registry import REGISTRY_DIR, InstanceIdentity
from ida_nexus._runtime import AnalysisState, APIError
from ida_nexus._server import NexusHTTPServer
from ida_nexus.errors import RemoteError


@pytest.fixture(name="databases")
def database_servers(tmp_path):
    with ExitStack() as cleanup:

        def create(*, backend=None, gui=False):
            number = len(list(tmp_path.glob("*.exe")))
            source = tmp_path / f"sample-{number}.exe"
            source.write_bytes(b"input")
            idb = source.with_suffix(".i64")  # deliberately not <input>.i64
            idb.write_bytes(b"packed")
            server = NexusHTTPServer(
                backend or StaticBackend(),
                InstanceIdentity(
                    str(idb), str(source), "gui" if gui else "idalib", managed=not gui
                ),
                AnalysisState(),
                REGISTRY_DIR,
                heartbeat_interval=0.02,
                on_shutdown=lambda: server.release_registration(),
            )
            cleanup.callback(server.release_registration)
            cleanup.callback(server.stop)
            server.start()
            return server, idb, source

        yield create


@pytest.fixture
def manager(databases):
    events = []
    value = DatabaseManager(
        on_event=lambda event, fields: events.append((event, fields))
    )
    try:
        yield value, events
    finally:
        value.shutdown(timeout=2)


def test_repeated_open_preserves_selection_and_one_retained_lease(databases, manager):
    value, events = manager
    _a, first, _ = databases()
    _b, second, _ = databases()
    a = value.open_database(str(first), set_current=False)
    b = value.open_database(str(second), set_current=True)
    assert a["status"] == "current"  # first attachment becomes current
    reused = value.open_database(str(first), set_current=False)
    assert reused["instance_id"] == a["instance_id"] and reused["status"] == "attached"
    assert value.resolve_instance_id(None) == b["instance_id"]
    assert value.open_database(str(first), set_current=True)["status"] == "current"
    value.close_database(b["instance_id"])
    assert value.resolve_instance_id(None) == a["instance_id"]
    assert [name for name, _ in events].count("database_reused") == 2


def test_concurrent_duplicate_opens_retain_one_manager_attachment(databases, manager):
    value, events = manager
    _server, path, _ = databases()
    barrier = threading.Barrier(3)

    def open_database():
        barrier.wait(timeout=3)
        return value.open_database(str(path), set_current=True)["instance_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(open_database), pool.submit(open_database)
        barrier.wait(timeout=3)
        assert first.result(timeout=5) == second.result(timeout=5)
    assert [name for name, _ in events] == ["database_opened", "database_reused"]
    value.close_database(None)
    assert value.list_databases()["instances"] == []


def test_open_callback_can_shutdown_without_deadlocking(databases, manager):
    value, _ = manager
    _server, path, _ = databases()
    value._on_event = lambda event, _fields: (
        value.shutdown(timeout=2) if event == "database_opened" else None
    )
    value.open_database(str(path), set_current=True)
    assert value.list_databases()["instances"] == []
    with pytest.raises(DatabaseSelectionError, match="shutting down"):
        value.open_database(str(path), set_current=True)


def test_failed_background_open_reports_error_and_allows_retry(
    databases, manager, tmp_path, capsys
):
    value, _ = manager
    value.schedule_startup_open(str(tmp_path / "absent.exe"))
    with pytest.raises(DatabaseSelectionError, match="no open database"):
        value.resolve_instance_id(None)
    assert "Startup open failed" in capsys.readouterr().err
    _server, path, _ = databases()
    value.open_database(str(path), set_current=True)
    assert value.resolve_instance_id(None)


@pytest.mark.parametrize("during_install", [False, True])
def test_disconnect_during_open_never_returns_an_attached_instance(
    databases, manager, monkeypatch, during_install
):
    value, _ = manager
    _server, path, _ = databases()
    real_open = DatabaseHandle.open
    handles = []

    def disconnecting_open(*args, **kwargs):
        handle = real_open(*args, **kwargs)
        handles.append(handle)
        if during_install:

            def install(callback):
                handle._disconnected.set()
                callback(handle, "lost during callback installation")

            monkeypatch.setattr(handle, "set_disconnect_callback", install)
        else:
            handle._disconnected.set()
        return handle

    monkeypatch.setattr(DatabaseHandle, "open", disconnecting_open)
    try:
        with pytest.raises(DatabaseSelectionError, match="disconnected while opening"):
            value.open_database(str(path), set_current=True)
        assert value._instances == {}
    finally:
        # Setting the failure flag above deliberately bypasses monitor cleanup.
        for handle in handles:
            handle.close()


def test_custom_gui_database_disconnect_classifies_the_actual_idb(databases, manager):
    value, events = manager
    _server, idb, source = databases(gui=True)
    instance_id = value.open_database(str(source), set_current=True)["instance_id"]
    _, session = value._get_session(instance_id)
    write_id0(idb.with_suffix(".id0"), dirty=True)
    value._handle_disconnected(session.handle, "lost GUI")
    # Repeated notification must not duplicate events or retarget another IDB.
    value._handle_disconnected(session.handle, "duplicate")
    with pytest.raises(DatabaseCrashedError) as error:
        value.execute_python("1", None)
    assert Path(error.value.database_state["idb_path"]) == idb
    assert [name for name, _ in events].count("database_disconnected") == 1
    assert events[-1][1]["database_state"]["state"] == "crashed"
    session.handle.close()


@pytest.mark.parametrize("operation", ["execute", "wait", "save"])
@pytest.mark.parametrize("disconnect", [False, True])
def test_transport_failure_is_not_retried_or_misclassified(
    databases, manager, monkeypatch, operation, disconnect
):
    value, events = manager
    _server, path, _ = databases()
    instance_id = value.open_database(str(path), set_current=True)["instance_id"]
    _, session = value._get_session(instance_id)
    calls = []

    def fail(*_args, **_kwargs):
        calls.append(operation)
        if disconnect:
            session.handle._disconnected.set()
            value._handle_disconnected(session.handle, "connection lost")
        raise NexusConnectionError("response lost")

    method = {
        "execute": "execute_python",
        "wait": "wait_autoanalysis",
        "save": "save_database",
    }[operation]
    monkeypatch.setattr(session.handle, method, fail)
    try:
        with pytest.raises(
            DatabaseSelectionError if disconnect else NexusConnectionError
        ):
            if operation == "execute":
                value.execute_python("mutation()", instance_id)
            else:
                getattr(value, method)(instance_id)
        assert calls == [operation]
        assert "database_saved" not in [name for name, _ in events]
        assert session.handle.connected is not disconnect
    finally:
        session.handle.close()


@pytest.mark.parametrize(
    "operation",
    [
        "resolve_instance_id",
        "execute_python",
        "cancel_operation",
        "cancel_active",
        "wait_autoanalysis",
        "save_database",
    ],
)
@pytest.mark.parametrize("crashed", [False, True])
def test_disconnected_handle_is_rejected_before_monitor_callback(
    databases, manager, operation, crashed
):
    value, _ = manager
    _server, path, _ = databases()
    instance_id = value.open_database(str(path), set_current=True)["instance_id"]
    _, session = value._get_session(instance_id)
    if crashed:
        write_id0(path.with_suffix(".id0"), dirty=True)
    session.handle._disconnected.set()  # monitor has observed EOF but not notified manager
    args = (
        ("1", instance_id)
        if operation == "execute_python"
        else (instance_id, "request")
        if operation == "cancel_operation"
        else (instance_id,)
    )
    with pytest.raises(DatabaseCrashedError if crashed else DatabaseSelectionError):
        getattr(value, operation)(*args)


def test_incomplete_analysis_is_not_cached_and_explicit_save_is_reported(
    databases, manager, monkeypatch
):
    backend = StaticBackend()
    value, events = manager
    _server, path, _ = databases(backend=backend)
    instance_id = value.open_database(str(path), set_current=True)["instance_id"]
    monkeypatch.setattr(
        backend,
        "wait_autoanalysis",
        lambda _timeout: {"status": "running", "complete": False},
    )
    with pytest.raises(DatabaseSelectionError, match="autoanalysis did not complete"):
        value.ensure_autoanalysis(instance_id)
    monkeypatch.setattr(
        backend,
        "wait_autoanalysis",
        lambda _timeout: {"status": "complete", "complete": True},
    )
    value.ensure_autoanalysis(instance_id)
    monkeypatch.setattr(backend, "save_database", lambda: {"idb_path": str(path)})
    assert value.save_database(instance_id) == {"path": str(path)}
    assert events[-1][0] == "database_saved"
    monkeypatch.setattr(backend, "save_database", lambda: {"idb_path": None})
    saved_events = [event for event in events if event[0] == "database_saved"]
    with pytest.raises(DatabaseSelectionError, match="invalid path"):
        value.save_database(instance_id)
    assert [event for event in events if event[0] == "database_saved"] == saved_events


def test_save_failure_keeps_attachment_and_never_reports_success(
    databases, manager, monkeypatch
):
    backend = StaticBackend()
    value, events = manager
    server, path, _ = databases(backend=backend)
    instance_id = value.open_database(str(path), set_current=True)["instance_id"]
    with DatabaseHandle.attach(server.entry) as peer:

        def fail_save():
            raise APIError("save_failed", "disk full", status=500)

        monkeypatch.setattr(backend, "save_database", fail_save)
        with pytest.raises(RemoteError) as error:
            value.save_database(instance_id)
        assert error.value.code == "save_failed"
        assert "database_saved" not in [name for name, _fields in events]
        assert value.resolve_instance_id(None) == instance_id
        assert peer.execute_python("still usable")["result"]["code"] == "still usable"
        monkeypatch.setattr(backend, "save_database", lambda: {"idb_path": str(path)})
        assert value.save_database(instance_id) == {"path": str(path)}
        assert events[-1][0] == "database_saved"


def test_close_racing_with_another_close_does_not_release_a_successor(
    databases, manager, monkeypatch
):
    value, events = manager
    _server, path, _ = databases()
    instance_id = value.open_database(str(path), set_current=True)["instance_id"]
    original = value._database_info

    def close_before_snapshot(session):
        monkeypatch.setattr(value, "_database_info", original)
        value.close_database(instance_id)
        return original(session)

    monkeypatch.setattr(value, "_database_info", close_before_snapshot)
    with pytest.raises(DatabaseSelectionError, match="unknown database"):
        value.close_database(instance_id)
    assert [name for name, _ in events].count("database_released") == 1


@pytest.mark.parametrize(
    "options",
    [
        {"keepalive": -1},
        {"keepalive": float("inf")},
        {"idle_timeout": True},
        {"idle_timeout": 0},
        {"idle_timeout": "1"},
    ],
)
def test_invalid_manager_lifecycle_policy_is_rejected(options):
    with pytest.raises(ValueError):
        DatabaseManager(**options)


@pytest.mark.parametrize("timeout", [True, "1", 0, -1, float("nan"), float("inf")])
def test_invalid_execution_budget_is_rejected_before_database_lookup(timeout):
    with pytest.raises(ValueError, match="timeout"):
        DatabaseManager().execute_python("1", None, timeout=timeout)
