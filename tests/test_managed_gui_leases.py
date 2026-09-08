"""A hosted GUI obeys final-lease ownership; an external GUI does not."""

import threading

import pytest
from test_instance_management import StaticBackend

from ida_nexus import DatabaseHandle
from ida_nexus._registry import InstanceIdentity
from ida_nexus._runtime import AnalysisState
from ida_nexus._server import NexusHTTPServer


@pytest.mark.parametrize("managed", [True, False])
def test_gui_release_preserves_other_clients_and_only_managed_gui_exits(tmp_path, managed):
    exited = threading.Event()
    server = NexusHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(tmp_path / "sample.i64"), str(tmp_path / "sample"), "gui", managed),
        AnalysisState(), tmp_path / "registry", lease_grace=1,
        on_shutdown=exited.set,
    )
    server.start()
    try:
        with DatabaseHandle.attach(server.entry) as first, DatabaseHandle.attach(server.entry) as peer:
            first.close()
            assert peer.execute_python("still here")["result"]["code"] == "still here"
            assert not exited.is_set()
        assert exited.wait(1.5) is managed
    finally:
        server.stop()
        server.release_registration()
