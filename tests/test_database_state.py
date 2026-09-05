from __future__ import annotations

import os
from pathlib import Path

import pytest

import ida_nexus._resolver as resolver
from ida_nexus import (
    DatabaseBusyError,
    DatabaseOpenError,
    database_state,
    probe_database_state,
)
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
def test_probe_database_state_detects_a_live_lock(tmp_path: Path) -> None:
    import fcntl

    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    id0 = Path(expected_idb_path(source)).with_suffix(".id0")
    write_id0(id0, dirty=True)
    fd = os.open(id0, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert probe_database_state(source)["state"] == "in_use"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


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

    command = resolver._build_worker_command(
        source,
        expected,
        20.0,
        resolver.WorkerLaunchOptions(),
        launcher=["ida-nexus", "worker"],
        record_suffix="abcdef",
    )

    assert "--output-database" not in command


def test_custom_output_keeps_explicit_output_switch(tmp_path: Path) -> None:
    source = str(tmp_path / "sample.bin")
    expected = str(tmp_path / "custom" / "sample.i64")

    command = resolver._build_worker_command(
        source,
        expected,
        20.0,
        resolver.WorkerLaunchOptions(),
        launcher=["ida-nexus", "worker"],
        record_suffix="abcdef",
    )

    index = command.index("--output-database")
    assert command[index + 1] == expected


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
