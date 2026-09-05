"""Safety gates before starting IDA; inject failures only at OS/race boundaries."""

import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_database_state import write_id0

import ida_nexus._resolver as resolver
from ida_nexus import (
    AmbiguousDatabaseError,
    DatabaseBusyError,
    DatabaseOpenError,
    NoDatabaseInstanceError,
    WorkerStartError,
    probe_database_state,
)
from ida_nexus._registry import (
    REGISTRY_DIR,
    SPAWN_DIR,
    DiscoveredDatabase,
    FileLock,
    InstanceIdentity,
    InstanceRegistration,
    InstanceState,
    idb_key,
)
from ida_nexus.database_state import expected_idb_path


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"original input")
    return path


@pytest.fixture
def records(source):
    with ExitStack() as cleanup:

        def create(*, backend="idalib", state=InstanceState.READY, path=None):
            registration = InstanceRegistration(
                REGISTRY_DIR,
                InstanceIdentity(
                    str(path or expected_idb_path(source)), str(source), backend
                ),
                token="test-token",
            )
            cleanup.callback(registration.release)
            return DiscoveredDatabase(
                registration.publish(12345), state, "owner is draining"
            )

        yield create


def never_spawn(*_args):
    pytest.fail("unsafe state must not launch a worker")


@pytest.mark.parametrize("backend", ["gui", "idalib"])
@pytest.mark.parametrize(
    "ambiguous", [False, True], ids=["blocked-owner", "two-owners"]
)
def test_unavailable_or_ambiguous_owner_is_never_replaced(
    source, records, monkeypatch, backend, ambiguous
):
    owners = [records(backend=backend, state=InstanceState.BLOCKED)]
    if ambiguous:
        owners.append(records(backend=backend))
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: owners)
    error = AmbiguousDatabaseError if ambiguous else DatabaseBusyError
    with pytest.raises(error):
        resolver.resolve_instance(source, spawner=never_spawn)


@pytest.mark.parametrize("late_owner", [False, True])
def test_fresh_database_refuses_owner_on_either_side_of_spawn_lock(
    source, records, monkeypatch, late_owner
):
    owner = records()
    scans = iter([[], [owner]] if late_owner else [[owner]])
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: next(scans))
    with pytest.raises(DatabaseBusyError, match="fresh database"):
        resolver.resolve_instance(source, new_database=True, spawner=never_spawn)
    assert source.read_bytes() == b"original input"
    lock = FileLock(SPAWN_DIR / f"{idb_key(expected_idb_path(source))}.lock")
    try:
        lock.acquire(timeout=0)
    finally:
        lock.close()


def test_explicit_output_does_not_attach_to_gui_for_same_executable(
    source, records, monkeypatch
):
    gui = records(backend="gui")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [gui])
    assert resolver.resolve_instance(source, spawn=False) == gui.instance
    with pytest.raises(NoDatabaseInstanceError):
        resolver.resolve_instance(
            source,
            output_database=source.parent / "custom.i64",
            spawn=False,
            spawner=never_spawn,
        )


def test_missing_source_releases_spawn_lock_for_later_retry(source):
    source.unlink()
    with pytest.raises(FileNotFoundError):
        resolver.resolve_instance(source, spawner=never_spawn)
    lock = FileLock(SPAWN_DIR / f"{idb_key(expected_idb_path(source))}.lock")
    try:
        lock.acquire(timeout=0)
    finally:
        lock.close()


@pytest.mark.parametrize(
    "dirty", [False, True], ids=["clean-unpacked", "crashed-unpacked"]
)
def test_custom_unpacked_output_without_packed_base_is_preserved(source, dirty):
    output = source.parent / "custom.i64"
    id0 = output.with_suffix(".id0")
    write_id0(id0, dirty=dirty)
    original = id0.read_bytes()
    with pytest.raises(DatabaseOpenError, match="custom output"):
        resolver.resolve_instance(source, output_database=output, spawner=never_spawn)
    assert id0.read_bytes() == original
    assert not output.exists()


@pytest.mark.parametrize("failure", ["backup", "in_use", "unknown"])
def test_failed_or_racing_crash_backup_never_starts_worker(
    source, monkeypatch, failure
):
    idb = Path(expected_idb_path(source))
    idb.write_bytes(b"last saved database")
    id0 = idb.with_suffix(".id0")
    write_id0(id0, dirty=True)
    before = id0.read_bytes()
    original_backup = resolver._backup_unpacked_database

    def backup(state):
        if failure == "backup":
            raise OSError("disk full")
        result = original_backup(state)
        # The owner/state changes after the actual copy, before IDA opens it.
        changed = dict(state, state=failure, error="header changed")
        monkeypatch.setattr(resolver, "probe_database_state", lambda *_a, **_k: changed)
        return result

    monkeypatch.setattr(resolver, "_backup_unpacked_database", backup)
    error = DatabaseBusyError if failure == "in_use" else DatabaseOpenError
    with pytest.raises(error):
        resolver.resolve_instance(source, spawner=never_spawn)
    assert id0.read_bytes() == before
    assert idb.read_bytes() == b"last saved database"
    assert source.read_bytes() == b"original input"


def test_launcher_failure_reports_child_log_and_allows_retry(source, tmp_path):
    log = tmp_path / "123-abcdef.log"
    child_log = tmp_path / "456-abcdef.log"
    child_log.write_text(
        "IDA could not open database: loader failure", encoding="utf-8"
    )
    calls = []

    def failed_spawn(*_args):
        calls.append(True)
        return SimpleNamespace(pid=123, poll=lambda: 7), log

    for _ in range(2):
        with pytest.raises(WorkerStartError, match="status 7") as error:
            resolver.resolve_instance(source, spawner=failed_spawn)
        assert "loader failure" in str(error.value)
    assert len(calls) == 2
    assert probe_database_state(source)["state"] == "missing"


def test_worker_ready_for_wrong_database_is_never_returned(
    source, records, monkeypatch, tmp_path
):
    wrong = records(path=tmp_path / "wrong.i64")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [wrong])
    with pytest.raises(WorkerStartError, match="expected"):
        resolver._await_ready(
            SimpleNamespace(pid=wrong.instance.pid),
            str(source),
            tmp_path / "123-abcdef.log",
            time.monotonic() + 1,
        )


def test_startup_timeout_keeps_last_health_failure_and_log(
    source, records, monkeypatch, tmp_path
):
    blocked = records(state=InstanceState.BLOCKED)
    unrelated = records()
    # Give the unrelated record a different launcher identity.
    from dataclasses import replace

    unrelated = replace(unrelated, instance=replace(unrelated.instance, pid=999999))
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [unrelated, blocked])
    log = tmp_path / f"{blocked.instance.record_id}.log"
    log.write_text("waiting for analysis", encoding="utf-8")
    with pytest.raises(WorkerStartError, match="timed out") as error:
        resolver._await_ready(
            SimpleNamespace(pid=blocked.instance.pid, poll=lambda: None),
            expected_idb_path(source),
            log,
            time.monotonic() + 0.03,
        )
    assert "owner is draining" in str(error.value)
    assert "waiting for analysis" in str(error.value)
