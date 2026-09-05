"""Lease authorization must hold while requests queue, cancel, and drain."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_instance_management import StaticBackend
from test_manager_scenarios import (
    database_servers,  # noqa: F401 -- shared server fixture
)
from test_nexus_server import request

from ida_nexus import DatabaseHandle, RemoteError


class HeldBackend(StaticBackend):
    def __init__(self):
        super().__init__()
        self.started = threading.Event()
        self.finish = threading.Event()
        self.executed = []
        self.cancelled = []

    def execute_python(self, code, *args, **kwargs):
        self.executed.append(code)
        if code == "held":
            self.started.set()
            assert self.finish.wait(5), "test did not release active operation"
        return super().execute_python(code, *args, **kwargs)

    def cancel_active(self):
        self.cancelled.append(True)


def test_foreign_cancellation_duplicate_request_and_busy_shutdown_preserve_active_operation(
    databases,
):
    backend = HeldBackend()
    server, _, _ = databases(backend=backend)
    with (
        DatabaseHandle.attach(server.entry) as writer,
        DatabaseHandle.attach(server.entry) as peer,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        execution = pool.submit(writer.execute_python, "held", operation_id="same-id")
        try:
            assert backend.started.wait(2)
            status, reply, _ = request(
                server,
                "POST",
                "/cancel_operation",
                {"lease_id": peer._lease_id, "operation_id": "same-id"},
            )
            assert status == 200 and reply["result"]["cancelled"] is False
            status, reply, _ = request(
                server,
                "POST",
                "/execute_python",
                {
                    "lease_id": writer._lease_id,
                    "operation_id": "same-id",
                    "code": "duplicate",
                },
            )
            assert status == 409 and reply["error"]["code"] == "duplicate_operation"
            peer.close()
            status, reply, _ = request(
                server,
                "POST",
                "/shutdown_database",
                {"lease_id": writer._lease_id, "save": False},
            )
            assert status == 409 and reply["error"]["code"] == "instance_busy"
            assert backend.cancelled == []
            assert backend.executed == ["held"]
        finally:
            backend.finish.set()
        assert execution.result(timeout=3)["result"]["code"] == "held"
        assert writer.execute_python("next")["result"]["code"] == "next"


@pytest.mark.parametrize("action", ["cancel", "release"])
def test_queued_request_cannot_run_after_its_lease_is_cancelled_or_released(
    databases, action
):
    backend = HeldBackend()
    server, _, _ = databases(backend=backend)
    with (
        DatabaseHandle.attach(server.entry) as active,
        DatabaseHandle.attach(server.entry) as queued,
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        running = pool.submit(active.execute_python, "held", operation_id="active")
        try:
            assert backend.started.wait(2)
            waiting = pool.submit(
                request,
                server,
                "POST",
                "/execute_python",
                {
                    "lease_id": queued._lease_id,
                    "operation_id": "queued",
                    "code": "must-not-run",
                },
            )
            # Read the server response on an independent RPC socket so lease
            # monitor cleanup cannot close the socket we are asserting on.
            # Wait for the real server to publish queued intent, without sleeps
            # or replacing its synchronization. Then act before backend entry.
            with server._activity:
                assert server._activity.wait_for(
                    lambda: (queued._lease_id, "queued") in server._pending_operations,
                    timeout=2,
                )
            if action == "cancel":
                status, reply, _ = request(
                    server,
                    "POST",
                    "/cancel_operation",
                    {"lease_id": queued._lease_id, "operation_id": "queued"},
                )
                assert status == 200 and reply["result"]["cancelled"] is True
            else:
                status, _, _ = request(
                    server, "POST", "/release_lease", {"lease_id": queued._lease_id}
                )
                assert status == 200
            assert backend.cancelled == []  # the active lease belongs to a peer
        finally:
            backend.finish.set()
        assert running.result(timeout=3)["result"]["code"] == "held"
        status, reply, _ = waiting.result(timeout=3)
        assert status == 409
        assert reply["error"]["code"] == (
            "operation_cancelled" if action == "cancel" else "lease_released"
        )
        assert backend.executed == ["held"]
        assert active.execute_python("next")["result"]["code"] == "next"


@pytest.mark.parametrize(
    "endpoint", ["/execute_python", "/save_database", "/wait_autoanalysis"]
)
def test_released_lease_cannot_start_another_operation(databases, endpoint):
    server, _, _ = databases()
    with (
        DatabaseHandle.attach(server.entry) as peer,
        DatabaseHandle.attach(server.entry) as released,
    ):
        lease_id = released._lease_id
        released.close()
        status, reply, _ = request(
            server,
            "POST",
            endpoint,
            {"lease_id": lease_id, "operation_id": "late", "code": "must-not-run"},
        )
        assert status == 409 and reply["error"]["code"] == "lease_released"
        assert peer.execute_python("still usable")["result"]["code"] == "still usable"


def test_gui_lease_cannot_request_process_shutdown(databases):
    server, _, _ = databases(gui=True)
    with DatabaseHandle.attach(server.entry) as handle:
        with pytest.raises(RemoteError) as error:
            handle.shutdown_database(save=False)
        assert error.value.code == "shutdown_not_supported"
        assert handle.connected
        assert handle.execute_python("still usable")["result"]["code"] == "still usable"
