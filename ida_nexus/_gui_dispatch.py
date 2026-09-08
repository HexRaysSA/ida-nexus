"""GUI-thread admission independent of IDA's disabled autoanalysis queue."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any


class GuiDispatcher:
    def __init__(
        self, safe: Callable[[], bool], *, register_timer: Callable | None = None
    ):
        self.thread = threading.get_ident()
        self.safe = safe
        self.pending: queue.Queue = queue.Queue()
        self.closed = False
        self.timer = register_timer(50, self.tick) if register_timer else None

    def call(
        self, operation: Callable, *args: Any, timeout: float = 120, **kwargs: Any
    ) -> Any:
        if self.closed:
            raise RuntimeError("IDA GUI dispatcher is closed")
        if threading.get_ident() == self.thread:
            return operation(*args, **kwargs)
        future: Future = Future()
        self.pending.put((future, operation, args, kwargs))
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            if future.cancel():
                raise TimeoutError(
                    "IDA GUI is busy; queued operation was not executed"
                ) from None
            return future.result()  # The runtime owns cancellation once admitted.

    def tick(self) -> int:
        if self.closed:
            return -1
        if not self.safe():
            return 50
        try:
            future, operation, args, kwargs = self.pending.get_nowait()
        except queue.Empty:
            return 50
        if future.set_running_or_notify_cancel():
            try:
                future.set_result(operation(*args, **kwargs))
            except BaseException as exc:  # noqa: BLE001 -- marshal native callback failures to the waiting caller
                future.set_exception(exc)
        return 50

    def close(self) -> None:
        self.closed = True
        while True:
            try:
                future, *_ = self.pending.get_nowait()
            except queue.Empty:
                break
            if not future.done():
                future.set_exception(
                    RuntimeError("IDA GUI closed before operation admission")
                )


def create_dispatcher() -> GuiDispatcher:
    import ida_auto
    import ida_kernwin
    from PySide6.QtWidgets import QApplication

    return GuiDispatcher(
        lambda: (
            QApplication.activeModalWidget() is None
            and ida_auto.get_auto_state() == ida_auto.AU_NONE
        ),
        register_timer=ida_kernwin.register_timer,
    )
