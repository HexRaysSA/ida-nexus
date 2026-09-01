import ast
import asyncio
import builtins
import ctypes
import heapq
import inspect
import io
import math
import threading
import time
import traceback
import warnings
from collections import deque
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from weakref import WeakSet

from ._registry import BackendName, _event_origin_id
from .models import DatabaseChangeEvent, PythonExecutionResult

DEFAULT_TIMEOUT_SECONDS = 60.0
SAVE_TIMEOUT_SECONDS = 300.0
USER_CODE_FILENAME = "<ida-nexus>"
_OPERATION_INTERRUPT_GLOBAL = "__ida_nexus_operation_interrupt__"
AUTOANALYSIS_SLICE_SECONDS = 0.02
AUTOANALYSIS_SLICE_STEPS = 256


class APIError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


class CodeValidationError(ValueError):
    """The supplied code cannot be invoked with the available runtime values."""


class AnalysisState:
    """Thread-safe status for the initial-autoanalysis barrier."""

    def __init__(self) -> None:
        self.complete = threading.Event()
        self._completion_lock = threading.Lock()
        self._completion_callbacks: list[Callable[[], object]] = []
        self._status = "running"

    def mark_complete(self, status: str = "complete") -> None:
        """Settle the barrier as analyzed or intentionally disabled.

        A later explicit wait may advance ``disabled`` to ``complete``. Completion
        callbacks still run exactly once, when the barrier first becomes usable.
        """

        if status not in {"complete", "disabled"}:
            raise ValueError("analysis completion status must be complete or disabled")
        with self._completion_lock:
            if self.complete.is_set():
                if self._status == "disabled" and status == "complete":
                    self._status = status
                return
            self._status = status
            self.complete.set()
            callbacks = tuple(self._completion_callbacks)
            self._completion_callbacks.clear()
        for callback in callbacks:
            callback()

    def add_completion_callback(self, callback: Callable[[], object]) -> None:
        with self._completion_lock:
            if self.complete.is_set():
                run_now = True
            else:
                self._completion_callbacks.append(callback)
                run_now = False
        if run_now:
            callback()

    def snapshot(self) -> dict[str, Any]:
        with self._completion_lock:
            complete = self.complete.is_set()
            status = self._status
        return {"status": status, "complete": complete}


def reconcile_autoanalysis_state(
    analysis_state: AnalysisState,
    *,
    disabled_is_complete: bool = False,
) -> dict[str, Any]:
    """Reconcile hook-driven state with IDA's current main-thread state.

    GUI actions temporarily suspend the runtime autoanalyzer, so only IDA's
    persistent user-facing flag may classify analysis as intentionally disabled.
    Workers leave a disabled analyzer pending for an explicit/background wait.
    """

    import ida_auto

    if ida_auto.auto_is_ok():
        analysis_state.mark_complete()
    elif disabled_is_complete:
        import ida_ida

        if not ida_ida.inf_is_auto_enabled():
            analysis_state.mark_complete("disabled")
    return analysis_state.snapshot()


class _OperationInterrupt(BaseException):
    """Asynchronous exception used to stop Python code without tracing it."""


# Nexus runs on CPython through IDAPython. Injecting one private exception
# into the executing thread keeps pure-Python loops cancellable without
# installing a trace callback on every opcode. Use a void pointer so a null
# value can undo the injection if CPython ever reports multiple matching thread
# states (which should be impossible for a threading.get_ident() value).
_set_async_exc = ctypes.pythonapi.PyThreadState_SetAsyncExc
_set_async_exc.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
_set_async_exc.restype = ctypes.c_int


def _interrupt_thread(thread_id: int) -> bool:
    count = _set_async_exc(thread_id, id(_OperationInterrupt))
    if count > 1:
        _set_async_exc(thread_id, None)
        raise RuntimeError("CPython matched multiple Nexus execution threads")
    return count == 1


class _DeadlineScheduler:
    """One reusable daemon for execution deadlines across all runtimes."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._deadlines: list[tuple[float, int]] = []
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._next_token = 0
        self._thread: threading.Thread | None = None

    def schedule(self, delay: float, callback: Callable[[], None]) -> int:
        deadline = time.monotonic() + delay
        with self._condition:
            self._next_token += 1
            token = self._next_token
            self._callbacks[token] = callback
            heapq.heappush(self._deadlines, (deadline, token))
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run,
                    name="ida-nexus-deadlines",
                    daemon=True,
                )
                self._thread.start()
            self._condition.notify()
            return token

    def cancel(self, token: int) -> None:
        with self._condition:
            if self._callbacks.pop(token, None) is not None:
                self._condition.notify()

    def _run(self) -> None:
        while True:
            callback: Callable[[], None] | None = None
            with self._condition:
                while callback is None:
                    while (
                        self._deadlines and self._deadlines[0][1] not in self._callbacks
                    ):
                        heapq.heappop(self._deadlines)
                    if not self._deadlines:
                        self._condition.wait()
                        continue
                    deadline, token = self._deadlines[0]
                    delay = deadline - time.monotonic()
                    if delay > 0:
                        self._condition.wait(delay)
                        continue
                    heapq.heappop(self._deadlines)
                    callback = self._callbacks.pop(token, None)
            if callback is not None:
                try:
                    callback()
                except BaseException as exc:  # noqa: BLE001 -- keep the scheduler alive
                    warnings.warn(
                        f"Nexus deadline callback failed: {exc}",
                        RuntimeWarning,
                        stacklevel=1,
                    )


_deadline_scheduler = _DeadlineScheduler()

def _protect_operation_interrupt(module: ast.Module) -> None:
    """Keep submitted exception handlers from consuming Nexus cancellation."""

    for node in ast.walk(module):
        if not isinstance(node, (ast.Try, ast.TryStar)) or not node.handlers:
            continue
        anchor = node.handlers[0]
        interrupt_type = ast.copy_location(
            ast.Name(id=_OPERATION_INTERRUPT_GLOBAL, ctx=ast.Load()),
            anchor.type or anchor,
        )
        if isinstance(node, ast.TryStar):
            # A bare raise from ``except*`` preserves its synthetic exception
            # group. Raise a fresh sentinel for _run_sync's cancellation handler.
            reraised_interrupt = ast.copy_location(
                ast.Name(id=_OPERATION_INTERRUPT_GLOBAL, ctx=ast.Load()),
                anchor.type or anchor,
            )
            reraiser = ast.copy_location(
                ast.Raise(exc=reraised_interrupt),
                anchor,
            )
        else:
            reraiser = ast.copy_location(ast.Raise(), anchor)
        handler = ast.copy_location(
            ast.ExceptHandler(type=interrupt_type, name=None, body=[reraiser]),
            anchor,
        )
        node.handlers.insert(0, handler)


def _execute_user_code(
    code: str,
    namespace: dict[str, Any],
    runtime: dict[str, Any],
    filename: str | None = None,
) -> Any:
    if not filename:
        filename = USER_CODE_FILENAME

    stripped = code.strip()
    if not stripped:
        raise CodeValidationError("code must not be empty")

    module = ast.parse(stripped, filename=filename, mode="exec")
    _protect_operation_interrupt(module)
    namespace[_OPERATION_INTERRUPT_GLOBAL] = _OperationInterrupt
    previous_entrypoints = {
        name: namespace.get(name) for name in ("run", "execute", "main")
    }
    # `result` is the legacy per-call output slot, not durable REPL state.
    # Ordinary names remain untouched in the persistent namespace.
    namespace.pop("result", None)
    try:
        if len(module.body) == 1 and isinstance(module.body[0], ast.Expr):
            expression = ast.Expression(module.body[0].value)
            return eval(
                compile(expression, filename, "eval"),
                namespace,
                namespace,
            )

        if module.body and isinstance(module.body[-1], ast.Expr):
            prefix = ast.Module(body=module.body[:-1], type_ignores=module.type_ignores)
            if prefix.body:
                exec(  # noqa: S102 -- intentional Nexus surface
                    compile(prefix, filename, "exec"),
                    namespace,
                    namespace,
                )
            expression = ast.Expression(module.body[-1].value)
            return eval(
                compile(expression, filename, "eval"),
                namespace,
                namespace,
            )

        exec(  # noqa: S102 -- intentional Nexus surface
            compile(module, filename, "exec"),
            namespace,
            namespace,
        )
        for name in ("run", "execute", "main"):
            candidate = namespace.get(name)
            if callable(candidate) and candidate is not previous_entrypoints[name]:
                return _invoke_callable(candidate, runtime)
        return namespace.get("result")
    finally:
        namespace.pop("result", None)


def _format_user_traceback(error: BaseException, trace_filename: str) -> str | None:
    """Format only the supplied-code portion of an execution failure."""

    if isinstance(error, SyntaxError):
        return "".join(traceback.format_exception_only(error))
    frames = traceback.extract_tb(error.__traceback__)
    first_user_frame = next(
        (
            index
            for index, frame in enumerate(frames)
            if frame.filename == trace_filename
        ),
        None,
    )
    if first_user_frame is None:
        return None
    return (
        "Traceback (most recent call last):\n"
        + "".join(traceback.format_list(frames[first_user_frame:]))
        + "".join(traceback.format_exception_only(error))
    )


def _invoke_callable(
    function: Callable[..., Any],
    runtime: dict[str, Any],
) -> Any:
    signature = inspect.signature(function)
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            continue
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            for name, value in runtime.items():
                kwargs.setdefault(name, value)
            continue
        if parameter.name not in runtime:
            if parameter.default is inspect.Parameter.empty:
                raise CodeValidationError(
                    f"missing runtime value for parameter '{parameter.name}'. "
                    f"Available names: {', '.join(sorted(runtime))}"
                )
            continue
        value = runtime[parameter.name]
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[parameter.name] = value
    return function(*args, **kwargs)


def _suppress_ida_domain_warnings() -> None:
    warnings.filterwarnings(
        "ignore",
        category=Warning,
        module=r"^ida_domain(?:\.|$)",
    )


def create_autoanalysis_hook(analysis_state: AnalysisState) -> Any:
    """Create an IDB hook without importing IDA when this module is imported."""

    import ida_idp

    class AutoAnalysisHook(ida_idp.IDB_Hooks):
        def auto_empty_finally(self) -> None:
            analysis_state.mark_complete()

    # The IDA stubs model SWIG constructors with spurious args/kwargs.
    hook_type: Any = AutoAnalysisHook
    return hook_type()


IDB_EVENT_QUEUE_LIMIT = 4096


class IdbChangeSubscriber:
    """One /idb_events connection's pending event queue."""

    def __init__(self) -> None:
        self.events: deque[DatabaseChangeEvent] = deque()
        self.overflowed = False


class IdbChangeState:
    """Fan out structured IDB events to active subscribers."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._revision = 0
        self._subscribers: WeakSet[IdbChangeSubscriber] = WeakSet()

    def subscribe(self) -> IdbChangeSubscriber:
        subscriber = IdbChangeSubscriber()
        with self._condition:
            self._subscribers.add(subscriber)
        return subscriber

    def record(
        self,
        event: dict[str, Any],
        operation_id: str | None = None,
        operation_label: str | None = None,
        origin_id: str | None = None,
    ) -> None:
        with self._condition:
            self._revision += 1
            recorded_event: DatabaseChangeEvent = {
                **event,
                "revision": self._revision,
                "operation_id": operation_id,
                "operation_label": operation_label,
                "origin_id": origin_id,
            }
            for subscriber in self._subscribers:
                if subscriber.overflowed:
                    continue
                if len(subscriber.events) == IDB_EVENT_QUEUE_LIMIT:
                    subscriber.events.clear()
                    subscriber.overflowed = True
                else:
                    subscriber.events.append(recorded_event)
            self._condition.notify_all()

    def wait(
        self, subscriber: IdbChangeSubscriber, timeout: float
    ) -> DatabaseChangeEvent | None:
        with self._condition:
            changed = self._condition.wait_for(
                lambda: bool(subscriber.events) or subscriber.overflowed,
                timeout=timeout,
            )
            if not changed:
                return None
            if subscriber.overflowed:
                raise OverflowError("IDB event subscriber fell behind")
            return subscriber.events.popleft()


def create_idb_change_hook(state: IdbChangeState) -> Any:
    """Create the structured IDB hook without importing IDA at module load."""

    from ._idb_events import IDBEventHook

    # The IDA stubs model SWIG constructors with spurious args/kwargs.
    hook_type: Any = IDBEventHook
    return hook_type(state.record)


class IDARuntime:
    """One uniform execute_sync runtime for GUI and idalib sessions."""

    def __init__(
        self,
        *,
        backend: BackendName,
        database: Any,
        analysis_state: AnalysisState,
        idb_change_state: IdbChangeState,
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
        unattributed_operation_label: str | None = None,
    ) -> None:
        # Library warnings would otherwise be captured as stderr and returned
        # to the agent alongside execution output.
        _suppress_ida_domain_warnings()

        # Outside IDA, ida-domain loads idapro and makes IDAPython modules
        # such as idaapi importable.
        import ida_domain as _ida_domain  # noqa: F401
        import idaapi

        version = tuple(
            int(part) for part in idaapi.get_kernel_version().split(".")[:2]
        )
        if version < (9, 4):
            raise RuntimeError("IDA Nexus requires IDA 9.4 or newer")

        if not math.isfinite(default_timeout) or default_timeout <= 0:
            raise ValueError("default_timeout must be a positive finite number")

        self.backend = backend
        self.database = database
        self.analysis_state = analysis_state
        self.idb_change_state = idb_change_state
        self.default_timeout = default_timeout
        self.unattributed_operation_label = unattributed_operation_label

        self._operation_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active_generation = 0
        self._active_kind: str | None = None
        self._active_cancel_event: threading.Event | None = None
        self._active_thread_id: int | None = None
        self._active_interrupt_error: APIError | None = None
        self._session_namespaces: dict[str, dict[str, Any]] = {}
        self._idb_change_hook: Any = None

    def _interrupt_active(
        self,
        generation: int,
        kind: str,
        error: APIError,
    ) -> None:
        """Interrupt the active native or Python operation exactly once."""

        import ida_kernwin

        with self._active_lock:
            if (
                self._active_generation != generation
                or self._active_kind != kind
                or self._active_cancel_event is None
                or self._active_interrupt_error is not None
            ):
                return
            self._active_interrupt_error = error
            self._active_cancel_event.set()
            ida_kernwin.set_cancelled()
            if self._active_thread_id is not None:
                _interrupt_thread(self._active_thread_id)

    def _run_sync(
        self,
        function: Callable[[], Any],
        *,
        kind: str,
        timeout: float | None,
        batch: bool = True,
        capture_output: bool = False,
        trace_filename: str | None = None,
    ) -> Any:
        import ida_kernwin
        import idc

        if not trace_filename:
            trace_filename = USER_CODE_FILENAME

        effective_timeout = timeout
        if effective_timeout is not None and (
            not math.isfinite(effective_timeout) or effective_timeout <= 0
        ):
            raise APIError(
                "invalid_timeout",
                "timeout must be a positive finite number",
            )
        outcome: tuple[bool, Any, str | None, str, str] | None = None

        with self._operation_lock:
            cancel_event = threading.Event()
            with self._active_lock:
                self._active_generation += 1
                generation = self._active_generation
                self._active_kind = kind
                self._active_cancel_event = cancel_event
                self._active_thread_id = None
                self._active_interrupt_error = None

            def invoke() -> int:
                nonlocal outcome
                old_batch: int | None = None
                deadline_token: int | None = None
                ida_kernwin.clr_cancelled()
                stdout_capture = io.StringIO()
                stderr_capture = io.StringIO()

                def timeout_operation() -> None:
                    assert effective_timeout is not None
                    self._interrupt_active(
                        generation,
                        kind,
                        APIError(
                            "operation_timeout",
                            f"{kind} timed out after {effective_timeout:.2f}s",
                            status=408,
                        ),
                    )

                def call_function() -> Any:
                    # Limit asynchronous interruption to user execution. Once
                    # this function returns, timeout/cancel callbacks can no
                    # longer replace an error while it is being marshalled.
                    try:
                        with self._active_lock:
                            self._active_thread_id = threading.get_ident()
                            pending_error = self._active_interrupt_error
                        if pending_error is not None:
                            raise pending_error
                        if capture_output:
                            with (
                                redirect_stdout(stdout_capture),
                                redirect_stderr(stderr_capture),
                            ):
                                return function()
                        return function()
                    finally:
                        with self._active_lock:
                            if self._active_generation == generation:
                                self._active_thread_id = None

                try:
                    if batch:
                        old_batch = idc.batch(1)
                    if effective_timeout is not None:
                        deadline_token = _deadline_scheduler.schedule(
                            effective_timeout,
                            timeout_operation,
                        )
                    result = call_function()
                    outcome = (
                        True,
                        result,
                        None,
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                except _OperationInterrupt:
                    with self._active_lock:
                        error = self._active_interrupt_error
                    if error is None:
                        error = APIError(
                            "operation_cancelled",
                            f"{kind} was interrupted",
                            status=409,
                        )
                    outcome = (
                        False,
                        error,
                        None,
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                except SystemExit as exc:
                    outcome = (
                        False,
                        APIError(
                            "system_exit",
                            f"{kind} raised SystemExit({exc.code!r})",
                            status=409,
                            details={
                                "exit_code": exc.code,
                                "stdout": stdout_capture.getvalue(),
                                "stderr": stderr_capture.getvalue(),
                            },
                        ),
                        repr(exc.code),
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                except BaseException as exc:  # noqa: BLE001 -- marshal any IDA callback failure
                    outcome = (
                        False,
                        exc,
                        _format_user_traceback(exc, trace_filename),
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                finally:
                    with self._active_lock:
                        if self._active_generation == generation:
                            self._active_thread_id = None
                    if deadline_token is not None:
                        _deadline_scheduler.cancel(deadline_token)
                    ida_kernwin.clr_cancelled()
                    if old_batch is not None:
                        idc.batch(old_batch)
                return 1

            try:
                ida_kernwin.execute_sync(invoke, ida_kernwin.MFF_WRITE)
                if outcome is None:
                    raise APIError(
                        "execute_sync_failed",
                        "IDA did not execute the synchronized request",
                        status=500,
                    )
                succeeded, value, formatted_traceback, stdout, stderr = outcome
            finally:
                with self._active_lock:
                    if self._active_generation == generation:
                        self._active_kind = None
                        self._active_cancel_event = None
                        self._active_thread_id = None
                        self._active_interrupt_error = None
                # Defend against a timeout racing with deadline cancellation.
                ida_kernwin.clr_cancelled()

        if succeeded:
            if capture_output:
                return PythonExecutionResult(
                    result=value,
                    stdout=stdout,
                    stderr=stderr,
                )
            return value
        if isinstance(value, APIError):
            if stdout:
                value.details["stdout"] = stdout
            if stderr:
                value.details["stderr"] = stderr
            raise value
        if isinstance(value, CodeValidationError):
            raise APIError("invalid_code", str(value), status=400) from value
        details: dict[str, Any] = {}
        if formatted_traceback is not None:
            details["traceback"] = formatted_traceback
        if stdout:
            details["stdout"] = stdout
        if stderr:
            details["stderr"] = stderr
        raise APIError(
            "execution_failed",
            str(value) or type(value).__name__,
            status=400,
            details=details,
        ) from value

    def cancel_active(self) -> None:
        """Request cancellation of the current IDA operation."""

        with self._active_lock:
            generation = self._active_generation
            kind = self._active_kind
        if kind is not None:
            self._interrupt_active(
                generation,
                kind,
                APIError(
                    "operation_cancelled",
                    f"{kind} was cancelled",
                    status=409,
                ),
            )

    def enable_idb_change_hook(self) -> None:
        """Install the database-change hook. Idempotent."""

        import ida_kernwin

        def install() -> int:
            if self._idb_change_hook is None:
                hook = create_idb_change_hook(self.idb_change_state)
                hook.operation_label = self.unattributed_operation_label
                if not hook.hook():
                    raise RuntimeError("IDA refused the database-change hook")
                self._idb_change_hook = hook
            return 1

        ida_kernwin.execute_sync(install, ida_kernwin.MFF_FAST)
        if self._idb_change_hook is None:
            raise RuntimeError("IDA did not install the database-change hook")

    def disable_idb_change_hook(self) -> None:
        """Remove the database-change hook. Idempotent."""

        import ida_kernwin

        def uninstall() -> int:
            if self._idb_change_hook is not None:
                self._idb_change_hook.unhook()
                self._idb_change_hook = None
            return 1

        ida_kernwin.execute_sync(uninstall, ida_kernwin.MFF_FAST)
        if self._idb_change_hook is not None:
            raise RuntimeError("IDA did not remove the database-change hook")

    def subscribe_idb_changes(self) -> IdbChangeSubscriber:
        return self.idb_change_state.subscribe()

    def wait_idb_change(
        self, subscriber: IdbChangeSubscriber, timeout: float
    ) -> DatabaseChangeEvent | None:
        return self.idb_change_state.wait(subscriber, timeout)

    def execute_python(
        self,
        code: str,
        timeout: float | None,
        *,
        lease_id: str | None = None,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> PythonExecutionResult:
        import ida_domain

        if not filename:
            filename = USER_CODE_FILENAME

        def execute() -> Any:
            hook = self._idb_change_hook
            previous_operation: tuple[str | None, str | None, str | None] | None = None
            if hook is not None:
                previous_operation = (
                    hook.operation_id,
                    hook.operation_label,
                    hook.origin_id,
                )
                hook.operation_id = operation_id
                hook.operation_label = operation_label
                hook.origin_id = (
                    _event_origin_id(lease_id) if lease_id is not None else None
                )
            try:
                runtime = {
                    "db": self.database,
                    "ida_domain": ida_domain,
                }
                if not persist_globals:
                    if lease_id is not None:
                        previous = self._session_namespaces.pop(lease_id, None)
                        if previous is not None:
                            previous.clear()
                    namespace = {
                        "__builtins__": builtins.__dict__,
                        "__name__": "__ida_nexus_execute__",
                        **runtime,
                    }
                else:
                    if lease_id is None:
                        raise APIError(
                            "invalid_lease",
                            "persist_globals requires an active lease",
                        )
                    namespace = self._session_namespaces.setdefault(lease_id, {})
                    # Runtime-owned globals remain valid even if a prior snippet
                    # rebound or deleted them; all other names behave like a REPL.
                    namespace.update(
                        {
                            "__builtins__": builtins.__dict__,
                            "__name__": "__ida_nexus_execute__",
                            **runtime,
                        }
                    )
                result = _execute_user_code(code, namespace, runtime, filename)
                if inspect.isawaitable(result):
                    result = asyncio.run(result)
                return result
            finally:
                if previous_operation is not None:
                    (
                        hook.operation_id,
                        hook.operation_label,
                        hook.origin_id,
                    ) = previous_operation

        return self._run_sync(
            execute,
            kind="execute",
            timeout=self.default_timeout if timeout is None else timeout,
            capture_output=True,
            trace_filename=filename,
        )

    def release_session(self, lease_id: str) -> None:
        """Release process-bound objects retained by one disconnected client."""

        def release() -> None:
            namespace = self._session_namespaces.pop(lease_id, None)
            if namespace is not None:
                # Explicitly break function -> __globals__ -> function cycles
                # so process-bound IDA objects are released with the lease,
                # not at a later cyclic-GC pass.
                namespace.clear()

        self._run_sync(
            release,
            kind="release_session",
            timeout=None,
            batch=False,
        )

    def advance_autoanalysis(
        self,
        *,
        max_steps: int = AUTOANALYSIS_SLICE_STEPS,
        max_seconds: float = AUTOANALYSIS_SLICE_SECONDS,
    ) -> dict[str, Any]:
        """Advance initial analysis for one bounded, interleavable slice."""

        import ida_auto
        import ida_idaapi

        if self.analysis_state.snapshot()["status"] == "complete":
            return self.analysis_state.snapshot()
        if max_steps <= 0 or not math.isfinite(max_seconds) or max_seconds <= 0:
            raise ValueError("autoanalysis slice limits must be positive")

        def advance() -> bool:
            previously_enabled = ida_auto.enable_auto(True)
            try:
                deadline = time.monotonic() + max_seconds
                for _ in range(max_steps):
                    if not ida_auto.auto_make_step(0, ida_idaapi.BADADDR):
                        return True
                    if time.monotonic() >= deadline:
                        break
                return False
            finally:
                if not previously_enabled:
                    ida_auto.enable_auto(False)

        completed = self._run_sync(
            advance,
            kind="analysis_slice",
            timeout=None,
        )
        if completed and ida_auto.auto_is_ok():
            self.analysis_state.mark_complete()
        return self.analysis_state.snapshot()

    def wait_autoanalysis(self, timeout: float | None) -> dict[str, Any]:
        import ida_auto

        initial_status = self.analysis_state.snapshot()
        if initial_status["complete"] and initial_status["status"] == "complete":
            return initial_status

        def wait() -> bool:
            previously_enabled = ida_auto.enable_auto(True)
            try:
                completed = bool(ida_auto.auto_wait())
            finally:
                if not previously_enabled:
                    ida_auto.enable_auto(False)
            if completed and ida_auto.auto_is_ok():
                self.analysis_state.mark_complete()
            return completed

        completed = self._run_sync(wait, kind="analysis", timeout=timeout)
        status = self.analysis_state.snapshot()
        if not completed and status["status"] != "complete":
            raise APIError(
                "analysis_cancelled",
                "Autoanalysis was cancelled before completion",
                status=409,
            )
        return status

    def save_database(self) -> dict[str, Any]:
        import ida_kernwin
        import ida_loader

        def save() -> dict[str, Any]:
            path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
            if not path:
                raise APIError(
                    "no_database", "No database is currently open", status=409
                )

            if self.backend == "gui":
                is_temporary = bool(ida_loader.is_database_flag(ida_loader.DBFL_TEMP))
                if is_temporary:
                    raise APIError(
                        "save_as_required",
                        "Use Save As in the IDA GUI before saving remotely",
                        status=409,
                    )
                saved = bool(ida_kernwin.process_ui_action("SaveBase"))
            else:
                saved = bool(ida_loader.save_database(path, 0))
            if not saved:
                raise APIError(
                    "save_failed",
                    "IDA failed to save the database",
                    status=500,
                )
            return {"saved": True, "idb_path": str(Path(path).resolve())}

        return self._run_sync(
            save,
            kind="save",
            timeout=SAVE_TIMEOUT_SECONDS,
            batch=False,
        )
