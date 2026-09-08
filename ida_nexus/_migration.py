"""Planned ownership handoffs. The coordinator is a library process, not MCP."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import asdict
from pathlib import Path

from ._registry import (
    HOST,
    LOG_DIR,
    SPAWN_DIR,
    DatabaseInstance,
    FileLock,
    ensure_private_directory,
)
from .errors import MigrationError, NexusConnectionError
from .gui import GuiLaunchOptions
from .paths import STATE_DIR, _find_console_script


def directory() -> Path:
    return ensure_private_directory(STATE_DIR / "migrations")


def record_path(instance: DatabaseInstance) -> Path:
    return directory() / (
        hashlib.sha256(instance.record_id.encode()).hexdigest() + ".json"
    )


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as output:
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def proof(instance: DatabaseInstance, transition: str) -> str:
    return hmac.new(
        instance._token.encode(),
        (transition + ":" + instance.idb_key).encode(),
        hashlib.sha256,
    ).hexdigest()


def transition_for(instance: DatabaseInstance) -> dict | None:
    try:
        value = json.loads(record_path(instance).read_text(encoding="utf-8"))
        if value["source"] != instance.record_id or value["expires"] < time.time():
            return None
        if not hmac.compare_digest(value["proof"], proof(instance, value["id"])):
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


def rpc(
    instance: DatabaseInstance, endpoint: str, payload: dict, timeout: float = 120
) -> dict:
    connection = http.client.HTTPConnection(HOST, instance.port, timeout=timeout)
    try:
        connection.request(
            "POST",
            endpoint,
            json.dumps(payload),
            {
                "Authorization": "Bearer " + instance._token,
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        value = json.loads(response.read())
        if response.status != 200:
            error = value.get("error", value)
            raise MigrationError(
                error.get("message", str(error))
                if isinstance(error, dict)
                else str(error)
            )
        return value.get("result", value)
    finally:
        connection.close()


def begin(
    instance: DatabaseInstance,
    target: str,
    gui: GuiLaunchOptions | None,
    timeout: float,
) -> dict:
    if target not in {"gui", "idalib"} or not 0 < timeout <= 600:
        raise ValueError(
            "migration requires gui/idalib and a timeout between 0 and 600 seconds"
        )
    if target == "gui":
        (
            gui or GuiLaunchOptions()
        ).resolved_executable()  # Fail before admission changes.
    lock = FileLock(directory() / (instance.idb_key + ".start.lock"))
    with lock:
        current = transition_for(instance)
        if current and current["state"] not in {"failed", "ready", "rolled_back"}:
            if current["target"] != target:
                raise MigrationError(
                    "A migration to the other backend is already in progress"
                )
            return current
        transition = uuid.uuid4().hex
        now = time.time()
        record = {
            "id": transition,
            "source": instance.record_id,
            "target": target,
            "state": "queued",
            "deadline": now + timeout,
            "expires": now + timeout + 900,
            "proof": proof(instance, transition),
            "database": instance.idb_path,
        }
        request = directory() / f"{transition}.request"
        write_json(
            request,
            {
                "instance": asdict(instance),
                "gui": asdict(gui) if gui else None,
                "record": record,
            },
        )
        write_json(record_path(instance), record)
        log = ensure_private_directory(LOG_DIR) / f"migration-{transition}.log"
        try:
            with log.open("ab") as output:
                subprocess.Popen(
                    [_find_console_script("ida-nexus"), "migrate-worker", str(request)],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=output,
                    **(
                        {
                            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP
                            | subprocess.CREATE_NO_WINDOW
                        }
                        if os.name == "nt"
                        else {"start_new_session": True}
                    ),
                )
        except Exception as exc:
            record.update(state="failed", error=str(exc))
            write_json(record_path(instance), record)
            request.unlink(missing_ok=True)
            raise
        return record


def wait(
    instance: DatabaseInstance, *, closed=None, timeout: float = 600
) -> tuple[DatabaseInstance, dict] | None:
    """Rebind only for an authenticated, explicit handoff of this incarnation."""
    from .instances import discover_databases

    record = transition_for(instance)
    if record is None:
        return None
    deadline = time.time() + timeout
    while True:
        if closed is not None and closed.is_set():
            raise NexusConnectionError("Database handle closed during migration")
        record = transition_for(instance)
        if record is None:
            raise MigrationError(
                "Migration record expired before ownership was established"
            )
        if record["state"] == "failed":
            raise MigrationError(record.get("error", "Database migration failed"))
        if record["state"] in {"ready", "rolled_back"}:
            for item in discover_databases():
                candidate = item.instance
                if (
                    candidate.record_id == record.get("successor")
                    and candidate.idb_key == instance.idb_key
                ):
                    return candidate, record
            raise MigrationError("Migration successor is no longer available")
        if time.time() >= min(deadline, record["deadline"] + 30):
            raise MigrationError(
                "Timed out waiting for database migration; no operation was replayed"
            )
        time.sleep(0.05)


def run(request_path: Path) -> int:
    from ._processes import wait_process_exit
    from ._resolver import WorkerLaunchOptions, _await_ready, spawn_worker
    from .gui import spawn_gui
    from .instances import wait_database_released

    request = json.loads(request_path.read_text(encoding="utf-8"))
    source = DatabaseInstance(**request["instance"])
    gui = (
        GuiLaunchOptions(**request["gui"]) if request.get("gui") else GuiLaunchOptions()
    )
    record = request["record"]
    released = False
    prepared = False
    source_gui = None
    lease_ids = []

    def update(**fields):
        record.update(fields)
        write_json(record_path(source), record)

    def remaining():
        value = record["deadline"] - time.time()
        if value <= 0:
            raise MigrationError("Migration deadline reached")
        return value

    def launch(target, config):
        options = WorkerLaunchOptions(auto_analysis=record.get("auto_analysis", True))
        environment = {
            "IDA_NEXUS_HANDOFF": json.dumps(
                {"idb_key": source.idb_key, "leases": lease_ids}
            )
        }
        if target == "gui":
            config = GuiLaunchOptions(
                config.executable, {**config.environment, **environment}
            )
            process, log = spawn_gui(
                source.idb_path, source.idb_path, 30, options, gui=config
            )
        else:
            process, log = spawn_worker(
                source.idb_path, source.idb_path, 30, options, environment=environment
            )
        return _await_ready(
            process, source.idb_path, log, time.monotonic() + remaining()
        )

    lock = FileLock(ensure_private_directory(SPAWN_DIR) / (source.idb_key + ".lock"))
    try:
        lock.acquire(remaining())
        update(state="draining")
        prepared = True
        state = rpc(
            source,
            "/migration/prepare",
            {"transition": record["id"], "timeout": remaining()},
            remaining() + 5,
        )
        source_gui = GuiLaunchOptions(**state["gui"]) if state.get("gui") else None
        lease_ids = state.get("leases", [])
        update(state="saved", auto_analysis=state.get("auto_analysis", True))
        update(state="releasing")
        try:
            rpc(
                source,
                "/migration/release",
                {"transition": record["id"]},
                min(remaining(), 10),
            )
        except (OSError, http.client.HTTPException):
            # A lost release acknowledgement is ambiguous. Reconcile ownership
            # without sending release twice or reopening a still-owned IDB.
            if not wait_database_released(source, timeout=remaining()):
                raise MigrationError(
                    "Source still owns the database after release acknowledgement was lost"
                ) from None
        released = True
        if not wait_database_released(source, timeout=remaining()):
            raise MigrationError("Source did not release native database ownership")
        # The GUI plugin terminates before IDA finishes its final native close.
        # Registration release alone is too early to admit the successor.
        if not wait_process_exit(source.pid, timeout=remaining()):
            raise MigrationError("Source IDA process did not finish closing")
        update(state="starting")
        successor = launch(record["target"], gui)
        update(state="ready", successor=successor.record_id, runtime_reset=True)
        return 0
    except Exception as exc:
        logging.getLogger(__name__).exception("Nexus migration failed")
        error = str(exc)
        if not released:
            if prepared:
                try:
                    rpc(source, "/migration/cancel", {"transition": record["id"]}, 5)
                except Exception:
                    logging.getLogger(__name__).exception(
                        "Migration cancellation failed"
                    )
            update(state="failed", error=error)
        else:
            # Never race a still-live target/source or silently restore old packed
            # data. Rollback is permitted only after native ownership is released.
            try:
                from .database_state import probe_database_state

                if probe_database_state(source.idb_path)["state"] == "in_use":
                    raise MigrationError(
                        "A process still owns the IDB; rollback was not attempted"
                    )
                record["deadline"] = time.time() + 120
                update(state="rolling_back", error=error)
                successor = launch(source.backend, source_gui or gui)
                update(
                    state="rolled_back",
                    successor=successor.record_id,
                    runtime_reset=True,
                )
            except Exception as rollback:  # noqa: BLE001 -- expose both failures without overwriting database files
                update(state="failed", error=f"{error}; rollback: {rollback}")
        return 1
    finally:
        lock.close()
        request_path.unlink(missing_ok=True)


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("request", type=Path)
    return run(parser.parse_args(argv).request)
