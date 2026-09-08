"""Ownership handoffs over real local HTTP connections, with fake IDA backends."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from test_nexus_server import RecordingBackend, make_server, request

from ida_nexus import DatabaseHandle
from ida_nexus._migration import proof, record_path, transition_for, write_json
from ida_nexus._registry import InstanceIdentity
from ida_nexus._runtime import AnalysisState, APIError
from ida_nexus._server import NexusHTTPServer


def transition(server, **updates):
    value = {
        "id": "test-transition",
        "source": server.entry.record_id,
        "target": "gui",
        "state": "draining",
        "deadline": time.time() + 30,
        "expires": time.time() + 60,
        "proof": proof(server.entry, "test-transition"),
    }
    value.update(updates)
    write_json(record_path(server.entry), value)
    return value


def test_migration_drains_admitted_work_and_cancel_restores_admission(tmp_path):
    server, backend = make_server(tmp_path)
    entered, finish = threading.Event(), threading.Event()
    original = backend.execute_python

    def execute(*args, **kwargs):
        entered.set()
        assert finish.wait(3)
        return original(*args, **kwargs)

    backend.execute_python = execute
    backend.prepare_migration = lambda timeout: {"saved": True}
    backend.cancel_migration = lambda: backend.calls.append(("cancel_migration",))
    try:
        with ThreadPoolExecutor(2) as pool:
            pending = pool.submit(
                request, server, "POST", "/execute_python", {"code": "mutation"}
            )
            assert entered.wait(2)
            record = transition(server)
            saving = pool.submit(
                request,
                server,
                "POST",
                "/migration/prepare",
                {"transition": record["id"], "timeout": 2},
            )
            deadline = time.monotonic() + 2
            while not server._migration and time.monotonic() < deadline:
                time.sleep(0.01)
            assert not saving.done()
            status, body, _ = request(
                server, "POST", "/execute_python", {"code": "not-admitted"}
            )
            assert status == 503 and body["error"]["code"] == "migrating"
            finish.set()
            assert pending.result()[0] == 200
            assert saving.result()[0] == 200
            assert (
                request(
                    server, "POST", "/migration/cancel", {"transition": record["id"]}
                )[0]
                == 200
            )
            assert (
                request(server, "POST", "/execute_python", {"code": "after-cancel"})[0]
                == 200
            )
            assert [
                call[1] for call in backend.calls if call[0] == "execute_python"
            ] == ["mutation", "after-cancel"]
    finally:
        finish.set()
        server.stop()
        server.release_registration()


def test_failed_save_keeps_source_and_never_allows_release(tmp_path):
    server, backend = make_server(tmp_path)

    def failed(_timeout):
        raise APIError("save_failed", "disk full", status=500)

    backend.prepare_migration = failed
    try:
        record = transition(server)
        payload = {"transition": record["id"]}
        assert request(server, "POST", "/migration/prepare", payload)[0] == 500
        assert request(server, "POST", "/migration/release", payload)[0] == 409
        assert server.save_on_shutdown
        assert request(server, "POST", "/migration/cancel", payload)[0] == 200
        assert (
            request(server, "POST", "/execute_python", {"code": "source-still-usable"})[
                0
            ]
            == 200
        )
    finally:
        server.stop()
        server.release_registration()


def test_two_handles_and_change_subscription_follow_only_signed_successor(
    tmp_path, monkeypatch
):
    from ida_nexus._registry import scan_instances

    monkeypatch.setattr(
        "ida_nexus.instances.discover_databases", lambda: scan_instances(tmp_path)
    )
    source, _backend = make_server(tmp_path)
    source.analysis_state.mark_complete()
    handles = [DatabaseHandle.attach(source.entry) for _ in range(2)]
    events = handles[0].subscribe_idb_events()
    destination = None
    old_entry = source.entry
    try:
        record = transition(source)
        source.stop()
        source.release_registration()
        analysis = AnalysisState()
        analysis.mark_complete()
        destination = NexusHTTPServer(
            RecordingBackend(analysis),
            InstanceIdentity(old_entry.idb_path, old_entry.exe_path, "gui"),
            analysis,
            tmp_path,
            record_suffix="abcdef",
        )
        destination.start()
        record.update(state="ready", successor=destination.entry.record_id)
        write_json(record_path(old_entry), record)
        for handle in handles:
            assert handle.execute_python("after-migration")["code"] == "after-migration"
            assert handle.instance.record_id == destination.entry.record_id
            assert handle.runtime_generation == 1
            assert handle.connected
        reset = next(events)
        assert reset["event_name"] == "runtime_reset"
        assert reset["runtime_generation"] == 1
        destination.backend.record_idb_event("renamed")
        assert next(events)["event_name"] == "renamed"
    finally:
        events.close()
        for handle in handles:
            handle.close()
        source.stop()
        source.release_registration()
        if destination:
            destination.stop()
            destination.release_registration()


def test_forged_or_expired_transition_cannot_rebind(tmp_path):
    server, _ = make_server(tmp_path)
    try:
        transition(server, proof="forged")
        assert transition_for(server.entry) is None
        transition(server, expires=0)
        assert transition_for(server.entry) is None
        assert (
            request(
                server, "POST", "/migration/prepare", {"transition": "test-transition"}
            )[0]
            == 409
        )
    finally:
        server.stop()
        server.release_registration()


def test_handoff_reservations_survive_first_reconnected_client_closing(tmp_path):
    server, _ = make_server(tmp_path)
    try:
        server._handoff_leases = {"first", "slower"}
        server._handoff_deadline = time.monotonic() + 30
        assert server._lease_opened("first", 0) is not None
        assert server._handoff_leases == {"slower"}
        server._detach_lease("first")
        assert not server._shutdown_requested
        assert server._lease_opened("slower", 0) is not None
        assert not server._pending_handoffs()
    finally:
        server.stop()
        server.release_registration()


def test_abandoned_handoff_reservations_expire(tmp_path):
    server, _ = make_server(tmp_path)
    try:
        server._handoff_leases = {"closed-during-migration"}
        server._handoff_deadline = time.monotonic() - 1
        assert not server._pending_handoffs()
        assert server.client_count == 0
    finally:
        server.stop()
        server.release_registration()
