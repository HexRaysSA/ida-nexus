"""Real process, IDA, disk, and transport tests using disposable input copies."""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import pytest

from ida_nexus import (
    DatabaseBusyError,
    DatabaseCrashedError,
    DatabaseDisconnectedError,
    DatabaseHandle,
    DatabaseManager,
    DatabaseOpenOptions,
    DatabaseSelectionError,
    RemoteError,
    discover_databases,
    find_database_owner,
    probe_database_state,
    wait_database_released,
)

pytestmark = pytest.mark.idalib_e2e

SAMPLE = Path(__file__).with_name("crackme03.elf")
READ_NAME = "db.functions.get_name(next(iter(db.functions)))"
RENAME = """\
func = next(iter(db.functions))
assert db.functions.set_name(func, {name!r})
db.functions.get_name(func)
"""


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return Path(shutil.copyfile(SAMPLE, tmp_path / SAMPLE.name))


@pytest.fixture
def open_handle():
    # Register cleanup immediately, including when an assertion fails. These
    # handles own real worker processes and must finish before conftest removes
    # the isolated registry and pytest removes the temporary input directory.
    with ExitStack() as stack:
        instances = {}

        def open_database(path: Path | str, **options) -> DatabaseHandle:
            handle = DatabaseHandle.open(
                str(path), options=DatabaseOpenOptions(**options)
            )
            stack.callback(handle.close, wait_for_database=True, timeout=30)
            instances[handle.instance.record_id] = handle.instance
            return handle

        yield open_database
    for instance in instances.values():
        assert wait_database_released(instance, timeout=30), "test worker leaked"


@pytest.fixture
def manager():
    database_manager = DatabaseManager(open_timeout=120)
    try:
        yield database_manager
    finally:
        database_manager.shutdown(timeout=30)


def wait_until(predicate, *, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition did not become true in time"
        time.sleep(0.05)


# A separate Python client gives each opener its own locks and lease monitor.
# File barriers coordinate real processes without replacing Nexus internals.
CLIENT = """\
import json
import sys
import time
from pathlib import Path
from ida_nexus import DatabaseHandle

source, start, ready, release = map(Path, sys.argv[1:])
ready.with_suffix('.waiting').touch()
while not start.exists():
    time.sleep(0.05)
handle = DatabaseHandle.open(str(source))
try:
    handle.wait_autoanalysis(timeout=60)
    temporary = ready.with_suffix('.tmp')
    temporary.write_text(json.dumps({'record_id': handle.instance.record_id}), encoding='utf-8')
    temporary.replace(ready)
    while not release.exists():
        time.sleep(0.05)
    print(handle.execute_python('db.functions.get_name(next(iter(db.functions)))')['result'], flush=True)
finally:
    handle.close(wait_for_database=True, timeout=30)
"""


@pytest.fixture
def clients(tmp_path: Path):
    processes = []

    def start_client(source: Path, start: Path):
        index = len(processes)
        ready = tmp_path / f"client-{index}.json"
        release = tmp_path / f"release-{index}"
        process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                "-c",
                CLIENT,
                str(source),
                str(start),
                str(ready),
                str(release),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        processes.append((process, start, release))
        return process, ready, release

    try:
        yield start_client
    finally:
        for process, start, release in processes:
            release.touch()
            if process.poll() is None and start.exists():
                try:
                    # Let the client's finally block drain its real worker,
                    # including when the parent test failed an assertion.
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
            elif process.poll() is None:
                process.kill()
            process.communicate(timeout=10)


def await_client(process, ready: Path) -> dict:
    def ready_or_failed():
        if process.poll() is not None:
            pytest.fail(f"client exited before attaching: {process.communicate()}")
        return ready.exists()

    wait_until(ready_or_failed, timeout=120)
    return json.loads(ready.read_text(encoding="utf-8"))


def test_process_clients_share_one_worker_and_persist_changes(
    source, open_handle, clients, tmp_path
):
    start = tmp_path / "start"
    first, first_ready, first_release = clients(source, start)
    second, second_ready, second_release = clients(source, start)
    wait_until(
        lambda: (
            first_ready.with_suffix(".waiting").exists()
            and second_ready.with_suffix(".waiting").exists()
        )
    )
    start.touch()
    first_info = await_client(first, first_ready)
    second_info = await_client(second, second_ready)
    assert first_info == second_info

    observer = open_handle(source)
    instance = observer.instance
    assert instance.record_id == first_info["record_id"]
    assert instance.backend == "idalib" and instance.managed
    assert [item.instance.record_id for item in discover_databases()] == [
        instance.record_id
    ]
    assert probe_database_state(source)["state"] == "in_use"
    assert (
        observer.execute_python(RENAME.format(name="NEXUS_SHARED"))["result"]
        == "NEXUS_SHARED"
    )
    with pytest.raises(RemoteError) as error:
        observer.shutdown_database(save=False)
    assert error.value.code == "instance_shared"

    first_release.touch()
    output, errors = first.communicate(timeout=30)
    assert first.returncode == 0, errors
    assert output.strip() == "NEXUS_SHARED"
    assert not wait_database_released(instance, timeout=0)
    second_release.touch()
    output, errors = second.communicate(timeout=30)
    assert second.returncode == 0, errors
    assert output.strip() == "NEXUS_SHARED"
    assert observer.execute_python(READ_NAME)["result"] == "NEXUS_SHARED"

    observer.close(wait_for_database=True, timeout=30)
    assert wait_database_released(instance, timeout=0)
    assert probe_database_state(source)["state"] == "packed"
    assert find_database_owner(source) is None
    reopened = open_handle(instance.idb_path)
    assert reopened.instance.record_id != instance.record_id
    assert reopened.recovery == "none"
    assert reopened.execute_python(READ_NAME)["result"] == "NEXUS_SHARED"


def test_abrupt_client_exit_releases_last_lease_and_saves(
    source, open_handle, clients, tmp_path
):
    start = tmp_path / "start"
    process, ready, _release = clients(source, start)
    start.touch()
    await_client(process, ready)
    instance = find_database_owner(source)
    assert instance is not None
    observer = open_handle(source)
    observer.execute_python(RENAME.format(name="NEXUS_BEFORE_CLIENT_EXIT"))
    observer.close(wait_for_database=True, timeout=30)
    # No observer lease: only the dead process's SSE connection retains IDA.
    process.kill()
    process.communicate(timeout=10)
    assert wait_database_released(instance, timeout=30)
    assert probe_database_state(source)["state"] == "packed"
    reopened = open_handle(source)
    assert reopened.execute_python(READ_NAME)["result"] == "NEXUS_BEFORE_CLIENT_EXIT"


def test_unregistered_idalib_owner_is_busy_until_it_closes(
    source, open_handle, tmp_path
):
    ready = tmp_path / "raw-ida-ready.json"
    release = tmp_path / "raw-ida-release"
    script = """\
import sys
import time
from pathlib import Path
from ida_domain import Database

source, ready, release = map(Path, sys.argv[1:])
with Database.open(str(source)) as db:
    ready.write_text('{}', encoding='utf-8')
    while not release.exists():
        time.sleep(0.05)
"""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", script, str(source), str(ready), str(release)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    try:
        await_client(process, ready)
        assert find_database_owner(source) is None
        assert probe_database_state(source)["state"] == "in_use"
        with pytest.raises(DatabaseBusyError, match="unregistered IDA session"):
            open_handle(source, startup_timeout=5)
        assert process.poll() is None
        release.touch()
        _output, errors = process.communicate(timeout=30)
        assert process.returncode == 0, errors
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)
    reopened = open_handle(source)
    assert reopened.recovery == "none"
    assert reopened.execute_python("len(list(db.functions))")["result"] > 0


def test_deferred_analysis_namespaces_and_real_idb_events(source, open_handle):
    writer = open_handle(source, auto_analysis=False)
    observer = open_handle(source)
    # A second attachment must not reconfigure the worker's analysis policy.
    assert writer.poll_autoanalysis()["complete"] is False
    assert (
        writer.execute_python("value = 42; value", persist_globals=True)["result"] == 42
    )
    assert (
        observer.execute_python("'value' in globals()", persist_globals=True)["result"]
        is False
    )
    assert writer.execute_python("value", persist_globals=True)["result"] == 42
    assert writer.execute_python("'value' in globals()")["result"] is False
    # Subscribe before analysis finishes to exercise deferred hook setup. Close
    # the stream before joining the reader, including after a failed assertion.
    with (
        ThreadPoolExecutor(max_workers=1) as pool,
        observer.subscribe_idb_events() as events,
    ):
        assert writer.wait_autoanalysis(timeout=60)["complete"]

        def renamed():
            return next(event for event in events if event["event_name"] == "renamed")

        first_event = pool.submit(renamed)
        writer.execute_python(
            RENAME.format(name="NEXUS_EVENT_ONE"),
            operation_id="rename-one",
            operation_label="E2E rename",
        )
        first = first_event.result(timeout=10)
        assert first["new_name"] == "NEXUS_EVENT_ONE"
        assert first["operation_id"] == "rename-one"
        assert first["operation_label"] == "E2E rename"
        assert writer.owns_event(first) and not observer.owns_event(first)
        second_event = pool.submit(renamed)
        observer.execute_python(RENAME.format(name="NEXUS_EVENT_TWO"))
        second = second_event.result(timeout=10)
        assert second["revision"] > first["revision"]
        assert second["operation_label"] is None
        assert observer.owns_event(second) and not writer.owns_event(second)


def test_idle_expiration_spares_active_request_and_other_lease(source, open_handle):
    peer = open_handle(source)
    peer.wait_autoanalysis(timeout=60)
    expired = threading.Event()
    timed = open_handle(source, idle_timeout=1)
    timed.set_disconnect_callback(lambda *_args: expired.set())
    assert (
        timed.execute_python("import time; time.sleep(2); 42", timeout=10)["result"]
        == 42
    )
    assert timed.connected
    assert expired.wait(15), "idle lease did not expire"
    with pytest.raises(DatabaseDisconnectedError):
        timed.execute_python("1")
    assert peer.execute_python("21 * 2")["result"] == 42
    assert not wait_database_released(peer.instance, timeout=0)


def test_keepalive_reuses_worker_then_exclusive_shutdown_discards_changes(
    source, open_handle
):
    original = open_handle(source, keepalive=10)
    original.wait_autoanalysis(timeout=60)
    original.execute_python(RENAME.format(name="NEXUS_SAVED"))
    original.save_database()
    instance = original.instance
    original.close(wait_for_database=True, timeout=30)
    assert not wait_database_released(instance, timeout=0.2)
    reused = open_handle(source)
    assert reused.instance.record_id == instance.record_id
    reused.execute_python(RENAME.format(name="NEXUS_DISCARDED"))
    reused.shutdown_database(save=False)
    assert wait_database_released(instance, timeout=30)
    reopened = open_handle(source)
    assert reopened.execute_python(READ_NAME)["result"] == "NEXUS_SAVED"


@pytest.mark.parametrize(
    "packed_base", [False, True], ids=["repair-unpacked", "restore-packed"]
)
def test_worker_crash_invalidates_handle_and_recovers_database(
    source, open_handle, packed_base
):
    disconnected = threading.Event()
    original = open_handle(source)
    original.set_disconnect_callback(lambda *_args: disconnected.set())
    original.wait_autoanalysis(timeout=60)
    original.execute_python(RENAME.format(name="NEXUS_SAVED"))
    if packed_base:
        original.save_database()
    original.execute_python(RENAME.format(name="NEXUS_FLUSHED"), flush_database=True)
    # os._exit bypasses IDA/Python shutdown without an OS crash dialog or dump.
    # The side-effect file also detects an accidental replay of this request.
    side_effect = source.parent / "crash-count"
    with pytest.raises(DatabaseCrashedError):
        original.execute_python(
            f"import os\nwith open({str(side_effect)!r}, 'a') as f:\n    f.write('once\\n')\nos._exit(73)",
            flush_database=True,
            timeout=10,
        )
    assert disconnected.wait(10)
    assert side_effect.read_text() == "once\n"
    state = probe_database_state(source)
    assert state["state"] == "crashed"
    assert state["packed_database_exists"] is packed_base
    crashed_files = {
        Path(path).name: Path(path).read_bytes() for path in state["unpacked_files"]
    }
    with pytest.raises(DatabaseDisconnectedError):
        original.execute_python("1")

    replacement = open_handle(source)
    assert replacement.instance.record_id != original.instance.record_id
    assert replacement.recovery == ("restored" if packed_base else "repaired")
    assert replacement.execute_python(READ_NAME)["result"] == (
        "NEXUS_SAVED" if packed_base else "NEXUS_FLUSHED"
    )
    assert not original.connected
    assert side_effect.read_text() == "once\n"
    assert Path(replacement.instance.idb_path).is_file(), (
        "repair must create a packed base"
    )
    backups = list(source.parent.glob("*.i64.crash-*"))
    if packed_base:
        assert len(backups) == 1
        assert {
            path.name: path.read_bytes() for path in backups[0].iterdir()
        } == crashed_files
    else:
        assert backups == []


def test_real_execution_timeout_and_cancellation_preserve_worker(
    source, open_handle, tmp_path
):
    handle = open_handle(source)
    handle.wait_autoanalysis(timeout=60)
    with pytest.raises(RemoteError) as error:
        handle.execute_python("while True: pass", timeout=0.2)
    assert error.value.code == "operation_timeout"
    assert handle.execute_python("6 * 7")["result"] == 42

    started = tmp_path / "executing"
    with ThreadPoolExecutor(max_workers=1) as pool:
        execution = pool.submit(
            handle.execute_python,
            f"from pathlib import Path\nPath({str(started)!r}).touch()\nwhile True: pass",
            timeout=15,
            operation_id="cancel-real-python",
        )
        wait_until(started.exists, timeout=10)
        assert handle.cancel_operation("cancel-real-python")
        with pytest.raises(RemoteError) as error:
            execution.result(timeout=10)
        assert error.value.code == "operation_cancelled"
    assert handle.execute_python("6 * 7")["result"] == 42


@pytest.mark.parametrize(
    "code", ["raise ValueError('bad user code')", "raise SystemExit(19)"]
)
def test_user_python_failure_preserves_database_and_peer(source, open_handle, code):
    writer = open_handle(source)
    peer = open_handle(source)
    writer.wait_autoanalysis(timeout=60)
    writer.execute_python(RENAME.format(name="NEXUS_BEFORE_ERROR"))
    with pytest.raises(RemoteError) as error:
        writer.execute_python(code)
    assert error.value.code == (
        "system_exit" if "SystemExit" in code else "execution_failed"
    )
    assert writer.connected and peer.connected
    assert peer.execute_python(READ_NAME)["result"] == "NEXUS_BEFORE_ERROR"
    assert writer.execute_python("6 * 7")["result"] == 42
    writer.save_database()
    writer.close(wait_for_database=True, timeout=30)
    assert not wait_database_released(peer.instance, timeout=0)
    peer.close(wait_for_database=True, timeout=30)
    assert (
        open_handle(source).execute_python(READ_NAME)["result"] == "NEXUS_BEFORE_ERROR"
    )


def test_custom_output_reopen_and_fresh_replacement(source, open_handle):
    output = source.parent / "chosen-name.i64"
    first = open_handle(source, output_database=str(output))
    first.wait_autoanalysis(timeout=60)
    original_name = first.execute_python(READ_NAME)["result"]
    first.execute_python(RENAME.format(name="NEXUS_CUSTOM_SAVED"))
    first.save_database()
    with pytest.raises(DatabaseBusyError):
        open_handle(source, output_database=str(output), new_database=True)
    assert first.execute_python(READ_NAME)["result"] == "NEXUS_CUSTOM_SAVED"
    first.close(wait_for_database=True, timeout=30)
    reopened = open_handle(source, output_database=str(output), image_base=0x800000)
    assert reopened.execute_python(READ_NAME)["result"] == "NEXUS_CUSTOM_SAVED"
    assert Path(reopened.instance.idb_path) == output
    reopened.close(wait_for_database=True, timeout=30)
    fresh = open_handle(source, output_database=str(output), new_database=True)
    fresh.wait_autoanalysis(timeout=60)
    assert fresh.execute_python(READ_NAME)["result"] == original_name
    assert fresh.recovery == "none"
    assert not source.with_name(source.name + ".i64").exists()


def test_manager_crash_requires_explicit_reopen_and_keeps_other_database(
    source, manager
):
    other = Path(shutil.copyfile(source, source.with_name("unaffected.elf")))
    dead = manager.open_database(str(source), set_current=True)["instance_id"]
    survivor = manager.open_database(str(other), set_current=False)["instance_id"]
    manager.ensure_autoanalysis(dead)
    manager.execute_python(RENAME.format(name="NEXUS_RECOVER_MANAGER"), dead)
    with pytest.raises(DatabaseCrashedError):
        manager.execute_python("import os; os._exit(74)", dead, flush_database=True)
    wait_until(lambda: dead not in manager._instances)
    with pytest.raises(DatabaseCrashedError):
        manager.execute_python("1", dead)
    assert manager.execute_python("6 * 7", survivor)["result"] == 42
    replacement = manager.open_database(str(source), set_current=True)["instance_id"]
    assert replacement != dead
    assert (
        manager.execute_python(READ_NAME, replacement)["result"]
        == "NEXUS_RECOVER_MANAGER"
    )
    with pytest.raises(DatabaseSelectionError):
        manager.execute_python("1", dead)


def test_manager_selection_aliases_and_shutdown_save_every_database(
    source, manager, open_handle
):
    second_source = Path(shutil.copyfile(source, source.with_name("second.elf")))
    first = manager.open_database(str(source), set_current=True)
    manager.ensure_autoanalysis(first["instance_id"])
    manager.execute_python(RENAME.format(name="NEXUS_FIRST"), None)
    second = manager.open_database(str(second_source), set_current=False)
    manager.ensure_autoanalysis(second["instance_id"])
    manager.execute_python(RENAME.format(name="NEXUS_SECOND"), second["instance_id"])
    assert manager.execute_python(READ_NAME, None)["result"] == "NEXUS_FIRST"
    instance = find_database_owner(source)
    assert instance is not None
    alias = manager.open_database(instance.idb_path, set_current=True)
    assert alias["instance_id"] == first["instance_id"]
    assert len(manager.list_databases()["instances"]) == 2
    manager.close_database(None)
    assert wait_database_released(instance, timeout=0), (
        "alias open retained a duplicate lease"
    )
    assert manager.execute_python(READ_NAME, None)["result"] == "NEXUS_SECOND"
    first_reopened = manager.open_database(str(source), set_current=False)
    assert first_reopened["instance_id"] != first["instance_id"]
    with pytest.raises(DatabaseSelectionError):
        manager.execute_python("1", first["instance_id"])
    manager.shutdown(timeout=30)
    manager.shutdown(timeout=30)
    with pytest.raises(DatabaseSelectionError, match="shutting down"):
        manager.open_database(str(source), set_current=True)
    for path, expected in [(source, "NEXUS_FIRST"), (second_source, "NEXUS_SECOND")]:
        assert probe_database_state(path)["state"] == "packed"
        assert find_database_owner(path) is None
        assert open_handle(path).execute_python(READ_NAME)["result"] == expected


def test_shutdown_waits_for_in_flight_real_idalib_open(
    source: Path, manager: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shutdown must include a real worker whose open has not been installed yet."""
    handle_opened = threading.Event()
    allow_open_to_finish = threading.Event()
    shutdown_finished = threading.Event()
    worker_instances: list[Any] = []
    open_errors: list[BaseException] = []
    shutdown_errors: list[BaseException] = []
    real_open = DatabaseHandle.open

    def blocked_open(
        cls: type[DatabaseHandle],
        path: str,
        *,
        options=None,
        on_disconnect=None,
    ) -> DatabaseHandle:
        del cls
        handle = real_open(path, options=options, on_disconnect=on_disconnect)
        worker_instances.append(handle.instance)
        handle_opened.set()
        if not allow_open_to_finish.wait(10):
            handle.close(wait_for_database=True, timeout=30)
            raise TimeoutError("test did not release the in-flight open")
        return handle

    monkeypatch.setattr(DatabaseHandle, "open", classmethod(blocked_open))

    def open_database() -> None:
        try:
            manager.open_database(str(source), set_current=True)
        except BaseException as error:  # noqa: BLE001 -- asserted by the test
            open_errors.append(error)

    def shutdown() -> None:
        try:
            manager.shutdown(timeout=30)
        except BaseException as error:  # noqa: BLE001 -- asserted by the test
            shutdown_errors.append(error)
        finally:
            shutdown_finished.set()

    open_thread = threading.Thread(target=open_database, name="e2e-open")
    shutdown_thread = threading.Thread(target=shutdown, name="e2e-shutdown")
    open_thread.start()
    try:
        assert handle_opened.wait(120), "real idalib worker did not open"
        shutdown_thread.start()
        returned_before_open_finished = shutdown_finished.wait(0.5)
    finally:
        allow_open_to_finish.set()
        open_thread.join(120)
        if shutdown_thread.ident is not None:
            shutdown_thread.join(120)

    assert not returned_before_open_finished
    assert not open_thread.is_alive()
    assert not shutdown_thread.is_alive()
    assert open_errors == []
    assert shutdown_errors == []
    assert worker_instances
    assert wait_database_released(worker_instances[0], timeout=10)
