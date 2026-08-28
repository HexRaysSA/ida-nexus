from unittest.mock import Mock

import pytest

from ida_nexus import mcp as mcp_api
from ida_nexus.manager import DatabaseManager


def test_programmatic_http_server_builds_manager_and_uses_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: dict[str, object] = {}

    class HostManager(DatabaseManager):
        def __init__(self, host_name: str, **kwargs: object) -> None:
            created.update(kwargs)
            created["host_name"] = host_name
            super().__init__(**kwargs)

    def serve_with_prefix(
        _host: str,
        _port: int,
        *,
        path_prefix: str,
    ) -> None:
        monkeypatch.setattr(mcp_api.mcp, "path_prefix", path_prefix.rstrip("/"))

    serve = Mock(side_effect=serve_with_prefix)
    stop = Mock()
    shutdown = Mock()
    trace = Mock()

    def hub_status() -> str:
        """Return the embedded hub status."""
        return "ready"

    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", DatabaseManager())
    monkeypatch.setattr(mcp_api.mcp, "serve", serve)
    monkeypatch.setattr(mcp_api.mcp, "stop", stop)
    monkeypatch.setattr(mcp_api, "_shutdown_server_state", shutdown)
    monkeypatch.setattr(mcp_api, "_start_mcp_trace", trace)
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)

    mcp_api.tool(hub_status)
    try:
        mcp_api.serve_http(
            "127.0.0.1",
            18737,
            database_manager_class=HostManager,
            database_manager_kwargs={"host_name": "test hub"},
            agent="test hub",
            path_prefix="/hex-rays/",
        )
    finally:
        mcp_api.mcp.tools.methods.pop("hub_status", None)

    assert created == {
        "host_name": "test hub",
        "on_event": mcp_api._trace_database_event,
    }
    assert isinstance(mcp_api.DATABASE_MANAGER, HostManager)
    serve.assert_called_once_with(
        "127.0.0.1",
        18737,
        path_prefix="/hex-rays/",
    )
    trace.assert_called_once_with(
        "http://127.0.0.1:18737/hex-rays/mcp",
        "test hub",
    )

    mcp_api.stop_http_server()
    stop.assert_called_once_with()
    shutdown.assert_called_once_with()


@pytest.mark.parametrize(
    ("host", "port"),
    [("", 18737), ("127.0.0.1", 0), ("127.0.0.1", 65536)],
)
def test_programmatic_http_server_rejects_invalid_address(
    host: str, port: int
) -> None:
    with pytest.raises(ValueError):
        mcp_api.serve_http(host, port)


def test_tool_rejects_builtin_name_collision() -> None:
    def open_database() -> None:
        pass

    with pytest.raises(ValueError, match="open_database"):
        mcp_api.tool(open_database)
