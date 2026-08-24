from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

import ida_nexus._runtime as runtime_module
from ida_nexus._runtime import (
    AnalysisState,
    IDARuntime,
    IdbChangeState,
    PythonExecutionResult,
    _execute_user_code,
    create_idb_change_hook,
    reconcile_autoanalysis_state,
)


def test_analysis_state_can_settle_disabled_then_finish_analysis() -> None:
    state = AnalysisState()
    callbacks: list[str] = []
    state.add_completion_callback(lambda: callbacks.append("ready"))

    state.mark_complete("disabled")
    assert state.snapshot() == {"status": "disabled", "complete": True}
    assert callbacks == ["ready"]

    state.mark_complete()
    assert state.snapshot() == {"status": "complete", "complete": True}
    assert callbacks == ["ready"]


def test_reconcile_uses_persistent_disable_not_runtime_disable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AnalysisState()
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        SimpleNamespace(auto_is_ok=lambda: False, is_auto_enabled=lambda: False),
    )
    fake_ida = SimpleNamespace(inf_is_auto_enabled=lambda: True)
    monkeypatch.setitem(sys.modules, "ida_ida", fake_ida)

    assert reconcile_autoanalysis_state(
        state,
        disabled_is_complete=True,
    ) == {"status": "running", "complete": False}

    fake_ida.inf_is_auto_enabled = lambda: False
    assert reconcile_autoanalysis_state(
        state,
        disabled_is_complete=True,
    ) == {"status": "disabled", "complete": True}


def test_idb_change_state_delivers_one_event_at_a_time() -> None:
    state = IdbChangeState()
    subscriber = state.subscribe()
    state.record({"event_name": "first", "timestamp": 1}, "operation-1")
    state.record({"event_name": "second", "timestamp": 2}, "operation-2")

    assert state.wait(subscriber, timeout=1.0) == {
        "event_name": "first",
        "timestamp": 1,
        "revision": 1,
        "operation_id": "operation-1",
        "operation_label": None,
        "origin_id": None,
    }
    assert state.wait(subscriber, timeout=1.0) == {
        "event_name": "second",
        "timestamp": 2,
        "revision": 2,
        "operation_id": "operation-2",
        "operation_label": None,
        "origin_id": None,
    }
    assert state.wait(subscriber, timeout=0.01) is None


def test_idb_change_state_fans_out_from_subscription_time() -> None:
    state = IdbChangeState()
    early = state.subscribe()
    state.record({"event_name": "first", "timestamp": 1})
    late = state.subscribe()
    state.record({"event_name": "second", "timestamp": 2})

    first = state.wait(early, 1.0)
    assert first is not None and first["event_name"] == "first"
    second = state.wait(early, 1.0)
    assert second is not None and second["event_name"] == "second"
    late_event = state.wait(late, 1.0)
    assert late_event is not None and late_event["event_name"] == "second"


def test_idb_change_state_bounds_slow_subscriber_queue() -> None:
    state = IdbChangeState()
    subscriber = state.subscribe()
    for revision in range(10_000):
        state.record({"event_name": "changed", "timestamp": revision})

    with pytest.raises(OverflowError, match="fell behind"):
        state.wait(subscriber, timeout=1.0)


def _namespace() -> dict[str, Any]:
    return {"__builtins__": __builtins__, "db": object()}


def test_execute_user_code_preserves_repl_namespace() -> None:
    namespace = _namespace()
    runtime = {"db": namespace["db"]}

    assert _execute_user_code("offset = 40", namespace, runtime) is None
    assert _execute_user_code("offset + 2", namespace, runtime) == 42
    assert (
        _execute_user_code("def add(value): return offset + value", namespace, runtime)
        is None
    )
    assert _execute_user_code("offset = 41", namespace, runtime) is None
    assert _execute_user_code("add(1)", namespace, runtime) == 42


def test_old_entrypoint_is_not_reused_and_result_is_per_call() -> None:
    namespace = _namespace()
    runtime = {"db": namespace["db"]}

    assert _execute_user_code("def run(db): return 7", namespace, runtime) == 7
    assert _execute_user_code("value = 1", namespace, runtime) is None
    assert _execute_user_code("result = 9", namespace, runtime) == 9
    assert _execute_user_code("result = 9", namespace, runtime) == 9
    assert _execute_user_code("other = 2", namespace, runtime) is None
    with pytest.raises(NameError):
        _execute_user_code("result", namespace, runtime)


def _inline_runtime(monkeypatch: pytest.MonkeyPatch) -> IDARuntime:
    monkeypatch.setitem(__import__("sys").modules, "ida_domain", SimpleNamespace())
    runtime = object.__new__(IDARuntime)
    runtime.database = object()
    runtime.default_timeout = 60.0
    runtime._session_namespaces = {}
    runtime._idb_change_hook = None

    def run_inline(
        function,
        *,
        kind: str,
        timeout: float | None,
        batch: bool = True,
        capture_output: bool = False,
        trace_filename: str | None = None,
    ) -> Any:
        result = function()
        if capture_output:
            return PythonExecutionResult(result=result, stdout="", stderr="")
        return result

    monkeypatch.setattr(runtime, "_run_sync", run_inline)
    return runtime


def test_autoanalysis_slices_release_before_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)
    runtime.analysis_state = AnalysisState()
    steps = iter((True, False))
    calls: list[object] = []

    def enable_auto(enabled: bool) -> bool:
        calls.append(("enable", enabled))
        return False

    def auto_make_step(start: int, end: int) -> bool:
        calls.append(("step", start, end))
        return next(steps)

    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        SimpleNamespace(
            enable_auto=enable_auto,
            auto_make_step=auto_make_step,
            auto_is_ok=lambda: True,
        ),
    )
    monkeypatch.setitem(sys.modules, "ida_idaapi", SimpleNamespace(BADADDR=-1))

    assert runtime.advance_autoanalysis(max_steps=1, max_seconds=1) == {
        "status": "running",
        "complete": False,
    }
    assert runtime.advance_autoanalysis(max_steps=1, max_seconds=1) == {
        "status": "complete",
        "complete": True,
    }
    assert calls == [
        ("enable", True),
        ("step", 0, -1),
        ("enable", False),
        ("enable", True),
        ("step", 0, -1),
        ("enable", False),
    ]


def test_explicit_wait_advances_disabled_barrier_to_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)
    runtime.analysis_state = AnalysisState()
    runtime.analysis_state.mark_complete("disabled")
    calls: list[object] = []

    def enable_auto(enabled: bool) -> bool:
        calls.append(("enable", enabled))
        return False

    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        SimpleNamespace(
            enable_auto=enable_auto,
            auto_wait=lambda: calls.append(("wait",)) or True,
            auto_is_ok=lambda: True,
        ),
    )

    assert runtime.wait_autoanalysis(None) == {
        "status": "complete",
        "complete": True,
    }
    assert calls == [("enable", True), ("wait",), ("enable", False)]


def test_cancelled_explicit_wait_does_not_accept_disabled_barrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)
    runtime.analysis_state = AnalysisState()
    runtime.analysis_state.mark_complete("disabled")
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        SimpleNamespace(
            enable_auto=lambda _enabled: False,
            auto_wait=lambda: False,
            auto_is_ok=lambda: False,
        ),
    )

    with pytest.raises(runtime_module.APIError, match="cancelled"):
        runtime.wait_autoanalysis(None)


def test_execution_operation_metadata_is_scoped_to_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = IdbChangeState()
    subscriber = state.subscribe()
    runtime = _inline_runtime(monkeypatch)
    hook = SimpleNamespace(
        operation_id=None,
        operation_label="IDA GUI",
        origin_id=None,
    )
    runtime._idb_change_hook = hook

    def record_change() -> None:
        state.record(
            {"event_name": "renamed", "timestamp": 1},
            hook.operation_id,
            hook.operation_label,
            hook.origin_id,
        )

    def execute_and_fail(*_args: Any) -> None:
        record_change()
        raise RuntimeError("failed after mutation")

    monkeypatch.setattr(runtime_module, "_execute_user_code", execute_and_fail)
    with pytest.raises(RuntimeError, match="failed after mutation"):
        runtime.execute_python(
            "mutate()",
            None,
            operation_id="request-1",
            operation_label="IDA Nexus TUI: Duncan",
            lease_id="lease-1",
        )

    attributed = state.wait(subscriber, timeout=1.0)
    assert attributed is not None
    assert attributed["operation_id"] == "request-1"
    assert attributed["operation_label"] == "IDA Nexus TUI: Duncan"
    assert attributed["origin_id"] == runtime_module._event_origin_id("lease-1")

    record_change()
    gui_event = state.wait(subscriber, timeout=1.0)
    assert gui_event is not None
    assert gui_event["operation_id"] is None
    assert gui_event["operation_label"] == "IDA GUI"
    assert gui_event["origin_id"] is None


def test_idb_hook_starts_with_runtime_unattributed_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)
    runtime.idb_change_state = IdbChangeState()
    runtime.unattributed_operation_label = "IDA GUI"
    hook = SimpleNamespace(operation_label=None, hook=lambda: True)
    monkeypatch.setattr(
        runtime_module,
        "create_idb_change_hook",
        lambda _state: hook,
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(MFF_FAST=0, execute_sync=lambda callback, _flags: callback()),
    )

    runtime.enable_idb_change_hook()

    assert runtime._idb_change_hook is hook
    assert hook.operation_label == "IDA GUI"


def test_idb_hook_installation_requires_execute_sync_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)
    monkeypatch.setattr(
        runtime_module,
        "create_idb_change_hook",
        lambda _state: SimpleNamespace(operation_label=None, hook=lambda: True),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(MFF_FAST=0, execute_sync=lambda _callback, _flags: -1),
    )

    with pytest.raises(RuntimeError, match="did not install"):
        runtime.enable_idb_change_hook()


def test_structured_hook_captures_renamed_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeIDBHooks:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

    monkeypatch.delitem(sys.modules, "ida_nexus._idb_events", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "ida_idp",
        SimpleNamespace(IDB_Hooks=FakeIDBHooks),
    )
    for module_name in (
        "ida_dirtree",
        "ida_frame",
        "ida_funcs",
        "ida_gdl",
        "ida_moves",
        "ida_range",
        "ida_segment",
        "ida_typeinf",
        "ida_ua",
    ):
        monkeypatch.setitem(sys.modules, module_name, SimpleNamespace())

    state = IdbChangeState()
    subscriber = state.subscribe()
    hook = create_idb_change_hook(state)
    hook.renamed(0x401000, "new_name", False, "old_name")

    event = state.wait(subscriber, timeout=1.0)
    assert event is not None
    assert event == {
        "event_name": "renamed",
        "timestamp": event["timestamp"],
        "ea": 0x401000,
        "new_name": "new_name",
        "local_name": False,
        "old_name": "old_name",
        "revision": 1,
        "operation_id": None,
        "operation_label": None,
        "origin_id": None,
    }
    assert isinstance(event["timestamp"], int)

    monkeypatch.setitem(
        sys.modules,
        "idc",
        SimpleNamespace(BADADDR=-1, get_name=lambda _ea: "target"),
    )
    refinfo = SimpleNamespace(
        target=0x401000,
        base=0,
        tdelta=4,
        flags=8,
        type=lambda: 1,
    )
    hook.changing_op_type(
        0x402000,
        0,
        SimpleNamespace(
            ri=refinfo,
            ec=SimpleNamespace(tid=0),
            path=SimpleNamespace(len=0),
            tid=0,
            strtype=0,
        ),
    )

    operand_event = state.wait(subscriber, timeout=1.0)
    assert operand_event is not None
    assert operand_event["event_name"] == "changing_op_type"
    assert operand_event["opinfo"] == {
        "kind": "offset",
        "refinfo": {
            "target": 0x401000,
            "base": 0,
            "tdelta": 4,
            "flags": 8,
            "ref_type": 1,
            "target_name": "target",
        },
    }


def test_stateless_execution_discards_persistent_lease_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)

    runtime.execute_python(
        "answer = 42",
        None,
        lease_id="agent",
        persist_globals=True,
    )
    namespace = runtime._session_namespaces["agent"]

    stateless = runtime.execute_python(
        "globals().get('answer')",
        None,
        lease_id="agent",
    )
    resumed = runtime.execute_python(
        "globals().get('answer')",
        None,
        lease_id="agent",
        persist_globals=True,
    )

    assert stateless["result"] is None
    assert resumed["result"] is None
    assert namespace == {}
    assert runtime._session_namespaces["agent"] is not namespace


def test_runtime_namespaces_are_isolated_and_released_per_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)

    def execute(code: str, lease_id: str) -> PythonExecutionResult:
        return runtime.execute_python(
            code,
            None,
            lease_id=lease_id,
            persist_globals=True,
        )

    runtime.execute_python("temporary = 1", None, lease_id="agent-a")
    fresh = runtime.execute_python(
        "globals().get('temporary')", None, lease_id="agent-a"
    )
    execute("answer = 42", "agent-a")
    first = execute("answer", "agent-a")
    second = execute("globals().get('answer')", "agent-b")
    execute("_adapter_state = {'retained': object()}", "agent-a")
    execute("db = None", "agent-a")
    refreshed = execute("db is None", "agent-a")

    assert fresh["result"] is None
    assert first["result"] == 42
    assert second["result"] is None
    assert refreshed["result"] is False
    namespace = runtime._session_namespaces["agent-a"]
    assert namespace["_adapter_state"]["retained"] is not None

    runtime.release_session("agent-a")

    assert namespace == {}
    assert "agent-a" not in runtime._session_namespaces
    reopened = execute("globals().get('answer')", "agent-a")
    assert reopened["result"] is None
