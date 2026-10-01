import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ida_nexus._gui_dispatch import GuiDispatcher


def test_gui_dispatch_waits_for_safe_state_and_runs_on_main_thread():
    safe = [False]
    dispatcher = GuiDispatcher(lambda: safe[0])
    main = threading.get_ident()
    with ThreadPoolExecutor() as pool:
        result = pool.submit(dispatcher.call, threading.get_ident)
        while dispatcher.pending.empty():
            threading.Event().wait(0.001)
        dispatcher.tick()
        assert not result.done()
        safe[0] = True
        dispatcher.tick()
        assert result.result(timeout=1) == main


def test_timed_out_queued_operation_never_executes_later():
    dispatcher = GuiDispatcher(lambda: True)
    called = []
    with ThreadPoolExecutor() as pool:
        result = pool.submit(
            dispatcher.call, lambda **kwargs: called.append(True), timeout=0.01
        )
        with pytest.raises(TimeoutError, match="GUI is busy"):
            result.result(timeout=1)
        dispatcher.tick()
        assert called == []


def test_nested_main_thread_call_is_immediate_and_failures_propagate():
    dispatcher = GuiDispatcher(lambda: True)
    assert dispatcher.call(lambda: dispatcher.call(lambda: 42)) == 42
    with ThreadPoolExecutor() as pool:
        result = pool.submit(dispatcher.call, lambda: 1 / 0)
        while dispatcher.pending.empty():
            threading.Event().wait(0.001)
        dispatcher.tick()
        with pytest.raises(ZeroDivisionError):
            result.result(timeout=1)
