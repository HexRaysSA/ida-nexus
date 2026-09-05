"""Exact attachment and at-most-once requests over real HTTP/SSE connections."""

import http.client
import time
from types import SimpleNamespace

import pytest
from test_manager_scenarios import (
    database_servers,  # noqa: F401 -- shared server fixture
)

import ida_nexus.handle as handle_module
from ida_nexus import DatabaseHandle, NexusConnectionError, RemoteError


@pytest.mark.parametrize("second_fails", [False, True])
def test_open_re_resolves_once_when_owner_dies_before_lease_handshake(
    databases, monkeypatch, second_fails
):
    first, path, _ = databases()
    second, _, _ = databases()
    entries = [first.entry, second.entry]
    resolves = []
    handshakes = []
    real_handshake = DatabaseHandle._open_lease

    def resolve(*_a, **_k):
        resolves.append(True)
        assert len(resolves) <= 2, "open must not retry indefinitely"
        return entries[len(resolves) - 1]

    def handshake(self, entry):
        handshakes.append(entry)
        if len(handshakes) == 1 or second_fails:
            raise NexusConnectionError("owner crossed shutdown boundary")
        return real_handshake(self, entry)

    monkeypatch.setattr(handle_module, "resolve_instance", resolve)
    monkeypatch.setattr(DatabaseHandle, "_open_lease", handshake)
    if second_fails:
        with pytest.raises(NexusConnectionError):
            DatabaseHandle.open(str(path))
    else:
        with DatabaseHandle.open(str(path)) as handle:
            assert handle.instance == second.entry
            assert handle.execute_python("1")["result"]["code"] == "1"
    assert handshakes == entries
    assert len(resolves) == 2


def test_exact_attach_never_resolves_a_replacement(databases, monkeypatch):
    server, _, _ = databases()

    def forbidden_resolve(*_a, **_k):
        pytest.fail("exact attachment must not resolve a different owner")

    def failed_handshake(*_a):
        raise NexusConnectionError("owner stopped")

    monkeypatch.setattr(handle_module, "resolve_instance", forbidden_resolve)
    monkeypatch.setattr(DatabaseHandle, "_open_lease", failed_handshake)
    with pytest.raises(NexusConnectionError, match="owner stopped"):
        DatabaseHandle.attach(server.entry)


@pytest.mark.parametrize(
    "failure", [TimeoutError, OSError, http.client.RemoteDisconnected]
)
def test_lost_response_never_replays_mutation_and_next_request_reconnects(
    databases, monkeypatch, failure
):
    server, _, _ = databases()
    with DatabaseHandle.attach(server.entry) as handle:
        effects = []
        execute = server.backend.execute_python

        def record_effect(code, *args, **kwargs):
            effects.append(code)
            return execute(code, *args, **kwargs)

        monkeypatch.setattr(server.backend, "execute_python", record_effect)
        connection = handle._rpc_connection_for(handle.instance, 5)
        getresponse = connection.getresponse

        def lose_reply():
            # The server really completed the POST. Lose only its response.
            response = getresponse()
            response.read()
            response.close()
            raise failure("reply lost after mutation")

        monkeypatch.setattr(connection, "getresponse", lose_reply)
        with pytest.raises(NexusConnectionError, match="reply lost"):
            handle.execute_python("mutate-once", operation_id="lost-request")
        assert effects == ["mutate-once"]
        assert handle.connected
        assert handle._active_operation_id is None
        assert handle.execute_python("next")["result"]["code"] == "next"
        assert effects == ["mutate-once", "next"]
        assert handle._rpc_connection is not connection


def test_idle_rpc_connection_is_recycled_without_replacing_lease(databases):
    server, _, _ = databases()
    with DatabaseHandle.attach(server.entry) as handle:
        handle.execute_python("first")
        connection = handle._rpc_connection
        origin = handle.event_origin_id
        handle._rpc_last_used = time.monotonic() - 60
        handle.execute_python("second")
        assert handle._rpc_connection is not connection
        assert connection.sock is None
        assert handle.event_origin_id == origin
        assert handle.instance == server.entry


@pytest.mark.parametrize(
    "status,body,error_type,match",
    [
        (200, b"not json", NexusConnectionError, "not valid JSON"),
        (502, b"proxy failure", NexusConnectionError, "HTTP 502"),
        (200, b"[]", NexusConnectionError, "not a JSON object"),
        (200, b'{"ok":false}', NexusConnectionError, "HTTP 200"),
        (
            409,
            b'{"error":{"code":"save_failed","message":"disk full","retryable":false}}',
            RemoteError,
            "disk full",
        ),
    ],
)
def test_invalid_or_failed_rpc_reply_does_not_poison_lease(
    databases, monkeypatch, status, body, error_type, match
):
    server, _, _ = databases()
    with DatabaseHandle.attach(server.entry) as handle:
        connection = handle._rpc_connection_for(handle.instance, 5)
        getresponse = connection.getresponse

        def replace_reply():
            response = getresponse()
            response.read()
            response.close()
            return SimpleNamespace(status=status, read=lambda: body, close=lambda: None)

        with monkeypatch.context() as patch:
            patch.setattr(connection, "getresponse", replace_reply)
            with pytest.raises(error_type, match=match) as error:
                handle.save_database()
            if error_type is RemoteError:
                assert error.value.code == "save_failed"
                assert error.value.details == {"retryable": False}
        assert handle.connected
        assert handle.execute_python("still usable")["result"]["code"] == "still usable"
