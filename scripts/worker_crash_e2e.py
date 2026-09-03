#!/usr/bin/env python3
"""Crash a disposable idalib worker and verify that IDA Nexus can replace it.

This intentionally writes to address zero inside the worker process. Never run it
against a database currently owned by an IDA GUI; the script refuses non-managed
idalib instances before issuing the crash.
"""

import argparse
import json
import threading
import time
from pathlib import Path
from typing import Any

from ida_nexus import (
    DatabaseManager,
    DatabaseSelectionError,
    NexusError,
    discover_databases,
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
        help=f"executable or IDB to open (default: {DEFAULT_DATABASE})",
    )
    parser.add_argument(
        "--disconnect-timeout",
        type=float,
        default=10.0,
        help="seconds to wait for the lease monitor to observe worker death",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database = args.database.expanduser().resolve()
    if not database.exists():
        raise SystemExit(f"database does not exist: {database}")
    if args.disconnect_timeout <= 0:
        raise SystemExit("--disconnect-timeout must be positive")

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

        matches = [
            item.instance
            for item in discover_databases()
            if item.instance.pid == worker_pid
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one registry entry for worker {worker_pid}, got {len(matches)}"
            )
        worker = matches[0]
        if worker.backend != "idalib" or not worker.managed:
            raise RuntimeError(
                "refusing to crash a database not owned by a managed idalib worker"
            )
        print_record(
            "opened",
            {
                **opened,
                **original,
                "record_id": worker.record_id,
                "managed": worker.managed,
            },
        )

        started = time.monotonic()
        try:
            manager.execute_python(CRASH_CODE, instance_id)
        except NexusError as error:
            print_record(
                "crash_call_error",
                {**error_record(error), "elapsed_seconds": time.monotonic() - started},
            )
        else:
            raise RuntimeError("address-zero write unexpectedly returned")

        if not disconnected.wait(args.disconnect_timeout):
            raise RuntimeError("lease monitor did not report worker disconnection")
        with events_lock:
            disconnect_events = [
                event for event in events if event["event"] == "database_disconnected"
            ]
        print_record("disconnect_event", disconnect_events[-1])

        try:
            manager.execute_python("1", instance_id, timeout=5.0)
        except DatabaseSelectionError as error:
            print_record("stale_instance_error", error_record(error))
        else:
            raise RuntimeError("the crashed manager instance remained usable")

        repaired = manager.open_database(str(database), set_current=True)
        replacement_id = repaired["instance_id"]
        manager.ensure_autoanalysis(replacement_id)
        replacement = manager.execute_python(PID_CODE, replacement_id)["result"]
        print_record("reopened", {**repaired, **replacement})

        if replacement_id == instance_id:
            raise RuntimeError("repair reused the invalid manager instance ID")
        if replacement["pid"] == worker_pid:
            raise RuntimeError("repair did not start a replacement worker")
        print_record("instances_after_repair", manager.list_databases())
        print("PASS: dead worker was rejected and replaced", flush=True)
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
