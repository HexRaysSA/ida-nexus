"""Native GUI lifecycle regressions. Enable explicitly with IDA_NEXUS_TEST_GUI."""

import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

from ida_nexus import (
    DatabaseHandle,
    DatabaseOpenOptions,
    GuiLaunchOptions,
    MigrationError,
)
from ida_nexus.manager import DatabaseManager

pytestmark = [
    pytest.mark.idalib_e2e,
    pytest.mark.skipif(
        not os.environ.get("IDA_NEXUS_TEST_GUI"),
        reason="GUI executable/display must be explicitly configured",
    ),
]


@pytest.fixture
def binary(tmp_path):
    source = tmp_path / "migration.elf"
    shutil.copyfile(Path(__file__).with_name("crackme03.elf"), source)
    return str(source)


def gui():
    return GuiLaunchOptions(os.environ["IDA_NEXUS_TEST_GUI"])


def counts(handle):
    return handle.execute_python(
        "{'functions': len(list(db.functions)), 'segments': len(list(db.segments))}"
    )["result"]


def test_native_round_trip_preserves_edits_handles_and_events(binary):
    a = DatabaseHandle.open(binary)
    b = DatabaseHandle.open(binary)
    manager = DatabaseManager()
    manager.open_database(binary, set_current=True)
    stream = None
    try:
        a.wait_autoanalysis()
        expected = counts(a)
        assert expected["functions"] == 28
        stream = b.subscribe_idb_events()
        observed = []

        def read():
            for event in stream:
                observed.append(event.get("event_name"))

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        a.execute_python(
            "import ida_name\nida_name.set_name(0x123e, 'migration_main', ida_name.SN_CHECK)"
        )
        a.execute_python("migration_python_global = 42", persist_globals=True)
        for backend in ("gui", "idalib"):
            a.ensure_backend(backend, gui=gui(), timeout=60)
            assert (
                manager.execute_python("len(list(db.functions))", None)["result"]
                == expected["functions"]
            )
            for handle in (a, b):
                assert counts(handle) == expected
                assert handle.instance.backend == backend
                assert (
                    handle.execute_python("import ida_name\nida_name.get_name(0x123e)")[
                        "result"
                    ]
                    == "migration_main"
                )
            assert (
                a.execute_python(
                    "globals().get('migration_python_global')", persist_globals=True
                )["result"]
                is None
            )
        deadline = time.monotonic() + 5
        while observed.count("runtime_reset") < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert observed.count("runtime_reset") == 2
    finally:
        manager.shutdown()
        if stream:
            stream.close()
        if a.connected and a.instance.backend == "gui":
            a.ensure_backend("idalib", timeout=60)
        a.close()
        b.close()


def test_native_gui_first_and_window_close_preserve_clients(binary):
    a = DatabaseHandle.open(
        binary, options=DatabaseOpenOptions(backend="gui", gui=gui())
    )
    b = DatabaseHandle.open(binary)
    try:
        a.wait_autoanalysis()
        expected = counts(a)
        assert expected["functions"] == 28
        assert a.execute_python("import ida_ida\nida_ida.inf_is_auto_enabled()")[
            "result"
        ]
        a.execute_python(
            "from PySide6.QtCore import QTimer\nfrom PySide6.QtWidgets import QApplication\nQTimer.singleShot(0, lambda: next(w for w in QApplication.topLevelWidgets() if w.inherits('QMainWindow')).close())\nTrue"
        )
        deadline = time.monotonic() + 65
        while a.instance.backend != "idalib" and time.monotonic() < deadline:
            time.sleep(0.05)
        assert a.instance.backend == "idalib"
        assert counts(a) == counts(b) == expected
    finally:
        if a.connected and a.instance.backend == "gui":
            a.ensure_backend("idalib", timeout=60)
        a.close()
        b.close()


def test_native_target_failure_rolls_back_without_losing_clients(binary):
    a = DatabaseHandle.open(binary)
    b = DatabaseHandle.open(binary)
    try:
        a.wait_autoanalysis()
        expected = counts(a)
        original_pid = a.instance.pid
        # A real executable that exits on IDA's command-line switches.
        with pytest.raises(MigrationError, match="restored"):
            a.ensure_backend("gui", gui=GuiLaunchOptions(sys.executable), timeout=30)
        assert a.instance.backend == "idalib" and a.instance.pid != original_pid
        assert counts(a) == counts(b) == expected
    finally:
        a.close()
        b.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX write-permission fixture")
def test_native_readonly_database_refuses_migration_before_release(binary):
    a = DatabaseHandle.open(binary)
    path = None
    try:
        a.wait_autoanalysis()
        a.ensure_backend("gui", gui=gui(), timeout=60)
        path = Path(a.instance.idb_path)
        path.chmod(0o444)
        with pytest.raises(MigrationError, match="not writable"):
            a.ensure_backend("idalib", timeout=30)
        assert a.connected and a.instance.backend == "gui"
        assert counts(a)["functions"] == 28
    finally:
        if path:
            path.chmod(0o644)
        if a.connected and a.instance.backend == "gui":
            a.ensure_backend("idalib", timeout=60)
        a.close()
