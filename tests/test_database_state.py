from __future__ import annotations

import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

import ida_nexus._resolver as resolver
from ida_nexus import (
    DatabaseBusyError,
    DatabaseOpenError,
    WorkerStartError,
    database_state,
    probe_database_state,
)
from ida_nexus._launch import worker_command
from ida_nexus.database_state import (
    _B_TREE_DIRTY_OFFSET,
    _B_TREE_HEADER_SIZE,
    _B_TREE_SIGNATURE,
    _B_TREE_SIGNATURE_OFFSET,
    _backup_unpacked_database,
    expected_idb_path,
)


def write_id0(path: Path, *, dirty: bool) -> None:
    header = bytearray(_B_TREE_HEADER_SIZE)
    header[_B_TREE_DIRTY_OFFSET] = int(dirty)
    header[_B_TREE_SIGNATURE_OFFSET:_B_TREE_HEADER_SIZE] = _B_TREE_SIGNATURE
    path.write_bytes(header)


def test_probe_database_state_distinguishes_disk_states(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    idb = Path(expected_idb_path(source))

    assert probe_database_state(source)["state"] == "missing"
    idb.write_bytes(b"packed")
    assert probe_database_state(source)["state"] == "packed"

    id0 = idb.with_suffix(".id0")
    write_id0(id0, dirty=True)
    crashed = probe_database_state(source)
    assert crashed["state"] == "crashed"
    assert crashed["dirty"] is True
    assert crashed["packed_database_exists"] is True

    write_id0(id0, dirty=False)
    unpacked = probe_database_state(source)
    assert unpacked["state"] == "unpacked"
    assert unpacked["dirty"] is False


@pytest.mark.parametrize("damage", ["truncated", "signature", "dirty-byte"])
def test_damaged_header_is_indeterminate_and_never_recovered(tmp_path, damage):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    id0 = Path(expected_idb_path(source)).with_suffix(".id0")
    write_id0(id0, dirty=True)
    header = bytearray(id0.read_bytes())
    if damage == "truncated":
        header = header[: _B_TREE_HEADER_SIZE - 1]
    elif damage == "signature":
        header[_B_TREE_SIGNATURE_OFFSET] ^= 0xFF
    else:
        header[_B_TREE_DIRTY_OFFSET] = 2
    id0.write_bytes(header)
    assert probe_database_state(source)["state"] == "unknown"
    with pytest.raises(DatabaseOpenError, match="indeterminate"):
        resolver.resolve_instance(source)
    assert id0.read_bytes() == header


@pytest.mark.parametrize("failure", ["missing-component", "copy", "fsync"])
def test_failed_backup_preserves_original_crash_components(
    tmp_path, monkeypatch, failure
):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    id0 = Path(expected_idb_path(source)).with_suffix(".id0")
    write_id0(id0, dirty=True)
    state = probe_database_state(source)
    before = id0.read_bytes()
    if failure == "missing-component":
        state["unpacked_files"].append(str(tmp_path / "vanished.id1"))
    else:

        def fail(*_args, **_kwargs):
            raise OSError("disk failure")

        if failure == "copy":
            monkeypatch.setattr(database_state.shutil, "copyfileobj", fail)
        else:
            monkeypatch.setattr(database_state.os, "fsync", fail)
    with pytest.raises(OSError):
        _backup_unpacked_database(state)
    assert id0.read_bytes() == before
    assert source.read_bytes() == b"input"


def test_probe_database_state_refuses_ambiguous_components(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    Path(expected_idb_path(source)).with_suffix(".id1").write_bytes(b"orphan")

    state = probe_database_state(source)

    assert state["state"] == "unknown"
    assert state["error"] == "unpacked database components exist without .id0"


def test_probe_database_state_refuses_network_lock_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    id0 = Path(expected_idb_path(source)).with_suffix(".id0")
    write_id0(id0, dirty=True)
    monkeypatch.setattr(database_state, "_network_filesystem", lambda _path: True)

    state = probe_database_state(source)

    assert state["state"] == "unknown"
    assert state["error"] == (
        "database is on a network filesystem where file locks are not reliable"
    )


@pytest.mark.skipif(os.name == "nt", reason="uses POSIX flock")
@pytest.mark.parametrize("lock_mode", ["LOCK_EX", "LOCK_SH"])
def test_probe_database_state_detects_a_live_lock(tmp_path: Path, lock_mode) -> None:
    import fcntl

    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    id0 = Path(expected_idb_path(source)).with_suffix(".id0")
    write_id0(id0, dirty=True)
    fd = os.open(id0, os.O_RDONLY)
    try:
        fcntl.flock(fd, getattr(fcntl, lock_mode) | fcntl.LOCK_NB)
        assert probe_database_state(source)["state"] == "in_use"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@pytest.mark.skipif(os.name == "nt", reason="uses POSIX flock")
@pytest.mark.parametrize("dirty", [False, True])
def test_concurrent_probes_do_not_mistake_each_other_for_live_owner(
    tmp_path, monkeypatch, dirty
):
    source = tmp_path / "sample.bin"
    id0 = Path(expected_idb_path(source)).with_suffix(".id0")
    write_id0(id0, dirty=dirty)
    lock_held = threading.Event()
    release_reader = threading.Event()
    second_probing = threading.Event()
    real_read = os.read
    real_header = database_state._locked_unpacked_header

    def paused_read(fd, size):
        if not lock_held.is_set():
            # The first probe already owns the real kernel lock. Reproduce
            # preemption here while the other disconnect thread probes too.
            lock_held.set()
            assert release_reader.wait(5), "test did not release the first probe"
        return real_read(fd, size)

    @contextmanager
    def observe_header(path):
        if lock_held.is_set():
            second_probing.set()
        with real_header(path) as result:
            yield result

    monkeypatch.setattr(database_state.os, "read", paused_read)
    monkeypatch.setattr(database_state, "_locked_unpacked_header", observe_header)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(probe_database_state, source)
        try:
            assert lock_held.wait(5)
            second = pool.submit(probe_database_state, source)
            assert second_probing.wait(5)
            # It must wait for our reader, not return a false "in_use" result.
            with pytest.raises(TimeoutError):
                second.result(timeout=0.1)
        finally:
            release_reader.set()
        expected = "crashed" if dirty else "unpacked"
        assert first.result(timeout=5)["state"] == expected
        assert second.result(timeout=5)["state"] == expected
    assert probe_database_state(source)["state"] == expected


def test_backup_preserves_crash_files_without_modifying_originals(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    idb = Path(expected_idb_path(source))
    idb.write_bytes(b"packed")
    id0 = idb.with_suffix(".id0")
    id1 = idb.with_suffix(".id1")
    write_id0(id0, dirty=True)
    id1.write_bytes(b"records")
    state = probe_database_state(source)

    backup = Path(_backup_unpacked_database(state))

    assert id0.read_bytes() == (backup / id0.name).read_bytes()
    assert id1.read_bytes() == (backup / id1.name).read_bytes()


def test_default_worker_open_never_uses_destructive_output_switch(
    tmp_path: Path,
) -> None:
    source = str(tmp_path / "sample.bin")
    expected = expected_idb_path(source)

    command = worker_command(
        "ida-nexus",
        source,
        expected,
        20.0,
        resolver.WorkerLaunchOptions(),
        record_suffix="abcdef",
    )

    assert not [switch for switch in command if switch.startswith("-o")]


def test_custom_output_keeps_explicit_output_switch(tmp_path: Path) -> None:
    source = str(tmp_path / "sample.bin")
    expected = str(tmp_path / "custom" / "sample.i64")

    command = worker_command(
        "ida-nexus",
        source,
        expected,
        20.0,
        resolver.WorkerLaunchOptions(),
        record_suffix="abcdef",
    )

    assert f"-o{expected}" in command


def test_resolver_refuses_unregistered_live_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    state = probe_database_state(source)
    state["state"] = "in_use"
    monkeypatch.setattr(resolver, "_scan_until", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        resolver, "probe_database_state", lambda *_args, **_kwargs: state
    )

    with pytest.raises(DatabaseBusyError, match="unregistered IDA session"):
        resolver.resolve_instance(source, timeout=1.0)


def test_resolver_requests_save_after_repairing_unpacked_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    state = probe_database_state(source)
    state.update(state="crashed", dirty=True, unpacked_files=[state["id0_path"]])
    observed: list[resolver.WorkerLaunchOptions] = []

    class SpawnObserved(Exception):
        pass

    def spawner(
        _source: str,
        _expected: str,
        _lease_grace: float,
        options: resolver.WorkerLaunchOptions,
    ):
        observed.append(options)
        raise SpawnObserved

    monkeypatch.setattr(resolver, "_scan_until", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        resolver, "probe_database_state", lambda *_args, **_kwargs: state
    )

    with pytest.raises(SpawnObserved):
        resolver.resolve_instance(source, timeout=1.0, spawner=spawner)

    assert observed[0].save_after_open is True


def test_resolver_refuses_indeterminate_unpacked_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    state = probe_database_state(source)
    state.update(
        state="unknown", error="bad header", unpacked_files=[state["id0_path"]]
    )
    monkeypatch.setattr(resolver, "_scan_until", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        resolver, "probe_database_state", lambda *_args, **_kwargs: state
    )

    with pytest.raises(DatabaseOpenError, match="indeterminate unpacked state"):
        resolver.resolve_instance(source, timeout=1.0)


def _failed_extraction_spawner(
    log_path: Path,
    *,
    dirty: bool = True,
    returncode: int | None = 1,
    backend: resolver.BackendName = "idalib",
    opened: bool = False,
):
    def spawner(_source, expected, _lease_grace, _options):
        idb = Path(expected)
        write_id0(idb.with_suffix(".id0"), dirty=dirty)
        idb.with_suffix(".id1").write_bytes(b"extracted")
        log_path.write_text(
            "IDA could not open database: corrupted\n", encoding="utf-8"
        )
        guard = log_path.with_suffix(".startup")
        guard.touch()
        if opened:
            guard.unlink()
        return resolver.SpawnedWorker(
            Mock(spec=subprocess.Popen, pid=4242, poll=Mock(return_value=returncode)),
            log_path,
            "abcdef",
            backend,
            guard,
        )

    return spawner


@pytest.mark.parametrize("dirty", [False, True], ids=["clean", "dirty"])
@pytest.mark.parametrize("custom_output", [False, True])
def test_failed_launches_discard_extraction_and_retry_packed_base(
    tmp_path, monkeypatch, dirty, custom_output
):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    output = tmp_path / "custom.i64" if custom_output else None
    idb = output or Path(expected_idb_path(source))
    idb.write_bytes(b"packed")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log", dirty=dirty)

    for _ in range(3):
        with pytest.raises(WorkerStartError, match="corrupted"):
            resolver.resolve_instance(
                source, output_database=output, timeout=1, spawner=spawner
            )
        state = probe_database_state(source, output_database=output)
        assert state["state"] == "packed"
        assert state["unpacked_files"] == []
        assert idb.read_bytes() == b"packed"
        assert list(tmp_path.glob(f"{idb.name}.crash-*")) == []


@pytest.mark.parametrize("packed", [False, True], ids=["backup-only", "packed"])
def test_failed_launch_preserves_original_crash_backup_without_copying_extraction(
    tmp_path, monkeypatch, packed
):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    idb = Path(expected_idb_path(source))
    if packed:
        idb.write_bytes(b"packed")
    write_id0(idb.with_suffix(".id0"), dirty=True)
    idb.with_suffix(".id1").write_bytes(b"client work")
    original_header = idb.with_suffix(".id0").read_bytes()
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log")

    # A fresh import without a packed base is protected only by this backup.
    for _ in range(2 if packed else 1):
        with pytest.raises(WorkerStartError, match="corrupted"):
            resolver.resolve_instance(
                source, new_database=not packed, timeout=1, spawner=spawner
            )

    backups = list(tmp_path.glob(f"{idb.name}.crash-*"))
    assert len(backups) == 1
    assert (backups[0] / idb.with_suffix(".id0").name).read_bytes() == original_header
    assert (backups[0] / idb.with_suffix(".id1").name).read_bytes() == b"client work"
    state = probe_database_state(source)
    assert state["state"] == ("packed" if packed else "missing")
    assert state["unpacked_files"] == []


@pytest.mark.parametrize(
    "initial, packed",
    [("unpacked", False), ("unpacked", True), ("crashed", False), ("missing", False)],
)
def test_failed_launch_preserves_unbacked_unpacked_database(
    tmp_path, monkeypatch, initial, packed
):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    idb = Path(expected_idb_path(source))
    if packed:
        idb.write_bytes(b"packed")
    if initial != "missing":
        write_id0(idb.with_suffix(".id0"), dirty=initial == "crashed")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log")

    with pytest.raises(WorkerStartError):
        resolver.resolve_instance(source, timeout=1, spawner=spawner)

    assert probe_database_state(source)["state"] == "crashed"
    assert idb.with_suffix(".id1").read_bytes() == b"extracted"
    assert list(tmp_path.glob(f"{idb.name}.crash-*")) == []


@pytest.mark.parametrize(
    "returncode, backend, removed",
    [
        (None, "idalib", False),
        (0, "idalib", False),
        (0, "idat", True),
        (0, "gui", True),
    ],
)
def test_failed_launch_cleans_only_after_worker_exit_is_certain(
    tmp_path, monkeypatch, returncode, backend, removed
):
    source = tmp_path / "sample.i64"
    source.write_bytes(b"packed")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    exit_is_fatal = resolver._launcher_exit_is_fatal
    monkeypatch.setattr(
        resolver,
        "_launcher_exit_is_fatal",
        lambda code, _platform: exit_is_fatal(code, "nt"),
    )
    spawner = _failed_extraction_spawner(
        tmp_path / "abcdef.log", returncode=returncode, backend=backend
    )

    with pytest.raises(WorkerStartError):
        resolver.resolve_instance(source, timeout=0.05, spawner=spawner)

    assert source.read_bytes() == b"packed"
    assert probe_database_state(source)["state"] == ("packed" if removed else "crashed")
    assert source.with_suffix(".id1").exists() is not removed


@pytest.mark.parametrize("state", ["in_use", "unknown"])
def test_failed_launch_preserves_unsafe_post_launch_components(
    tmp_path, monkeypatch, state
):
    source = tmp_path / "sample.i64"
    source.write_bytes(b"packed")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])

    # The initial packed state needs no header read. Simulate a new owner or
    # a damaged extraction when cleanup inspects the newly created .id0.
    @contextmanager
    def unsafe_header(_path):
        yield (True, None, None) if state == "in_use" else (False, b"", None)

    monkeypatch.setattr(database_state, "_locked_unpacked_header", unsafe_header)
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log")

    with pytest.raises(WorkerStartError):
        resolver.resolve_instance(source, timeout=1, spawner=spawner)

    assert probe_database_state(source)["state"] == state
    assert source.with_suffix(".id1").read_bytes() == b"extracted"


def test_failed_launch_reports_cleanup_error_without_hiding_startup_failure(
    tmp_path, monkeypatch
):
    source = tmp_path / "sample.i64"
    source.write_bytes(b"packed")
    id1 = source.with_suffix(".id1")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    remove = os.remove

    def fail_one_remove(path):
        if Path(path) == id1:
            raise PermissionError("cleanup denied")
        remove(path)

    monkeypatch.setattr(resolver.os, "remove", fail_one_remove)
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log")

    with pytest.raises(WorkerStartError, match="corrupted") as raised:
        resolver.resolve_instance(source, timeout=1, spawner=spawner)

    assert "cleanup denied" in str(raised.value)
    assert str(id1) in str(raised.value)
    assert id1.read_bytes() == b"extracted"
    assert probe_database_state(source)["state"] == "crashed"
    assert source.read_bytes() == b"packed"


def test_failed_readiness_after_native_open_preserves_new_work(tmp_path, monkeypatch):
    source = tmp_path / "sample.i64"
    source.write_bytes(b"packed")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log", opened=True)

    with pytest.raises(WorkerStartError):
        resolver.resolve_instance(source, timeout=1, spawner=spawner)

    assert probe_database_state(source)["state"] == "crashed"
    assert source.with_suffix(".id1").read_bytes() == b"extracted"


@pytest.mark.skipif(os.name == "nt", reason="uses POSIX flock")
@pytest.mark.parametrize("lock_mode", ["LOCK_EX", "LOCK_SH"])
def test_failed_extraction_cleanup_excludes_foreign_owner_until_last_unlink(
    tmp_path, monkeypatch, lock_mode
):
    import fcntl

    source = tmp_path / "sample.i64"
    source.write_bytes(b"packed")
    id0 = source.with_suffix(".id0")
    monkeypatch.setattr(resolver, "_scan_until", lambda *_a, **_k: [])
    remove = os.remove

    def try_foreign_owner(path):
        # A foreign IDA tries to acquire .id0 exactly when cleanup starts
        # deleting components. Real kernel locks must exclude both lock modes.
        with id0.open("rb") as file, pytest.raises(BlockingIOError):
            fcntl.flock(file.fileno(), getattr(fcntl, lock_mode) | fcntl.LOCK_NB)
        if Path(path) == id0:
            assert not source.with_suffix(".id1").exists()
        remove(path)

    monkeypatch.setattr(database_state.os, "remove", try_foreign_owner)
    spawner = _failed_extraction_spawner(tmp_path / "abcdef.log")

    with pytest.raises(WorkerStartError):
        resolver.resolve_instance(source, timeout=1, spawner=spawner)

    assert probe_database_state(source)["state"] == "packed"
    assert not source.with_suffix(".id1").exists()
