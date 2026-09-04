import os
import shutil
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from ida_nexus import DatabaseHandle, DatabaseManager, wait_database_released

_RUN_IDALIB_E2E = os.environ.get("IDA_NEXUS_RUN_IDALIB_E2E") == "1"


@pytest.mark.skipif(
    not _RUN_IDALIB_E2E,
    reason="set IDA_NEXUS_RUN_IDALIB_E2E=1 to run real idalib lifecycle tests",
)
def test_shutdown_waits_for_in_flight_real_idalib_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shutdown must include a real worker whose open has not been installed yet."""
    executable = tmp_path / "python.exe"
    shutil.copyfile(sys.executable, executable)

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
        assert allow_open_to_finish.wait(10)
        return handle

    monkeypatch.setattr(DatabaseHandle, "open", classmethod(blocked_open))
    manager = DatabaseManager(open_timeout=120)

    def open_database() -> None:
        try:
            manager.open_database(str(executable), set_current=True)
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
    shutdown_thread.join(120)

    assert not returned_before_open_finished
    assert not open_thread.is_alive()
    assert not shutdown_thread.is_alive()
    assert open_errors == []
    assert shutdown_errors == []
    assert worker_instances
    assert wait_database_released(worker_instances[0], timeout=10)
