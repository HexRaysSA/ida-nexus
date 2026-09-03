#!/usr/bin/env python3
"""Crash idalib with only a flushed unpacked IDB, then verify repair.

The input executable is copied to a temporary directory. The script mutates its
new database, flushes the unpacked files immediately before a null write kills
the worker, and verifies that reopening repairs and preserves that mutation.
"""

import argparse
import json
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from ida_nexus import (
    DatabaseCrashedError,
    DatabaseManager,
    NexusError,
    probe_database_state,
)

RENAME_CODE = """\
def run(db):
    func = next(iter(db.functions), None)
    if func is None:
        raise RuntimeError("database has no functions")
    if not db.functions.set_name(func, "NEXUS_CRASH_RECOVERY_MARK"):
        raise RuntimeError("function rename failed")
    return {"ea": func.start_ea, "name": db.functions.get_name(func)}
"""
POST_SAVE_RENAME_CODE = RENAME_CODE.replace(
    "NEXUS_CRASH_RECOVERY_MARK",
    "NEXUS_POST_SAVE_CRASH_MARK",
)


CRASH_CODE = """\
def run(db):
    import ctypes
    ctypes.memset(0, 0x41, 1)
    return "unreachable"
"""
PID_CODE = """\
def run(db):
    import os
    return {"pid": os.getpid(), "module": db.module}
"""
DEFAULT_DATABASE = Path(__file__).resolve().parents[1] / "tests" / "crackme03.elf"


def print_record(label: str, value: Any) -> None:
    print(f"{label}: {json.dumps(value, default=str, sort_keys=True)}", flush=True)


def error_record(error: Exception) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": type(error).__name__,
        "message": str(error),
    }
    for name in ("code", "status", "details"):
        if hasattr(error, name):
            record[name] = getattr(error, name)
    if error.__cause__ is not None:
        record["cause"] = {
            "type": type(error.__cause__).__name__,
            "message": str(error.__cause__),
        }
    return record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "database",
        nargs="?",
        type=Path,
        default=DEFAULT_DATABASE,
        help=f"executable to copy and open (default: {DEFAULT_DATABASE})",
    )
    parser.add_argument(
        "--disconnect-timeout",
        type=float,
        default=10.0,
        help="seconds to wait for the lease monitor to observe worker death",
    )
    parser.add_argument(
        "--packed-base",
        action="store_true",
        help="also save a packed base, then verify restore and crash-file backup",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.database.expanduser().resolve()
    if not source.exists():
        raise SystemExit(f"database does not exist: {source}")
    if args.disconnect_timeout <= 0:
        raise SystemExit("--disconnect-timeout must be positive")

    with tempfile.TemporaryDirectory(prefix="ida-nexus-crash-e2e-") as directory:
        database = Path(directory) / source.name
        shutil.copy2(source, database)
        initial_state = probe_database_state(database)
        if initial_state["state"] != "missing":
            raise RuntimeError(
                "the isolated input unexpectedly has existing database files"
            )

        events: list[dict[str, Any]] = []
        events_lock = threading.Lock()
        disconnected = threading.Event()

        def on_event(event: str, fields: dict[str, Any]) -> None:
            with events_lock:
                events.append({"event": event, **fields})
            if event == "database_disconnected":
                disconnected.set()

        manager = DatabaseManager(on_event=on_event)
        replacement_id: str | None = None
        try:
            opened = manager.open_database(str(database), set_current=True)
            instance_id = opened["instance_id"]
            manager.ensure_autoanalysis(instance_id)
            original = manager.execute_python(PID_CODE, instance_id)["result"]
            worker_pid = original["pid"]
            if opened["backend"] != "idalib":
                raise RuntimeError("isolated executable did not open in idalib")
            print_record("opened", {**opened, **original})

            mutation = manager.execute_python(RENAME_CODE, instance_id)["result"]
            print_record("mutation_before_crash", mutation)
            expected_name = mutation["name"]
            if args.packed_base:
                print_record(
                    "packed_base",
                    manager.save_database(instance_id),
                )
                post_save_mutation = manager.execute_python(
                    POST_SAVE_RENAME_CODE,
                    instance_id,
                )["result"]
                print_record("post_save_mutation", post_save_mutation)

            started = time.monotonic()
            try:
                manager.execute_python(
                    CRASH_CODE,
                    instance_id,
                    flush_database=True,
                )
            except DatabaseCrashedError as error:
                print_record(
                    "crash_call_error",
                    {
                        **error_record(error),
                        "database_state": error.database_state,
                        "elapsed_seconds": time.monotonic() - started,
                    },
                )
            except NexusError as error:
                raise RuntimeError(
                    f"crash was not characterized: {type(error).__name__}: {error}"
                ) from error
            else:
                raise RuntimeError("address-zero write unexpectedly returned")

            if not disconnected.wait(args.disconnect_timeout):
                raise RuntimeError("lease monitor did not report worker disconnection")
            with events_lock:
                disconnect_events = [
                    event
                    for event in events
                    if event["event"] == "database_disconnected"
                ]
            print_record("disconnect_event", disconnect_events[-1])

            crashed_state = probe_database_state(database)
            print_record("files_after_crash", crashed_state)
            if crashed_state["state"] != "crashed":
                raise RuntimeError("worker death did not leave a dirty unpacked IDB")
            if crashed_state["packed_database_exists"] is not args.packed_base:
                raise RuntimeError("packed IDB precondition did not match the scenario")

            try:
                manager.execute_python("1", instance_id, timeout=5.0)
            except DatabaseCrashedError as error:
                print_record("stale_instance_error", error_record(error))
            else:
                raise RuntimeError("the crashed manager instance remained usable")

            repaired = manager.open_database(str(database), set_current=True)
            replacement_id = repaired["instance_id"]
            manager.ensure_autoanalysis(replacement_id)
            replacement = manager.execute_python(
                f"""def run(db):
    import os
    func = db.functions.get_at({mutation["ea"]})
    return {{
        "pid": os.getpid(),
        "name": None if func is None else db.functions.get_name(func),
    }}
""",
                replacement_id,
            )["result"]
            print_record("reopened", {**repaired, **replacement})

            expected_recovery = "restored" if args.packed_base else "repaired"
            if repaired["recovery"] != expected_recovery:
                raise RuntimeError(
                    f"expected {expected_recovery} recovery, got {repaired['recovery']}"
                )
            if replacement_id == instance_id:
                raise RuntimeError("repair reused the invalid manager instance ID")
            if replacement["pid"] == worker_pid:
                raise RuntimeError("repair did not start a replacement worker")
            if replacement["name"] != expected_name:
                raise RuntimeError("recovery selected the wrong database state")

            repaired_state = probe_database_state(database)
            print_record("files_after_repair", repaired_state)
            if not repaired_state["packed_database_exists"]:
                raise RuntimeError("repair did not immediately create a packed base")
            if args.packed_base:
                idb = Path(crashed_state["idb_path"])
                backups = sorted(idb.parent.glob(f"{idb.name}.crash-*"))
                if len(backups) != 1:
                    raise RuntimeError(
                        f"expected one crash backup, found {len(backups)}"
                    )
                print_record(
                    "crash_backup",
                    {
                        "path": str(backups[0]),
                        "files": sorted(path.name for path in backups[0].iterdir()),
                    },
                )
            print_record("instances_after_repair", manager.list_databases())
            action = "restored" if args.packed_base else "repaired"
            print(
                f"PASS: crash was characterized and flushed work was {action}",
                flush=True,
            )
            return 0
        finally:
            if replacement_id is not None:
                try:
                    manager.close_database(replacement_id)
                except NexusError as error:
                    print_record("replacement_close_error", error_record(error))
            manager.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
