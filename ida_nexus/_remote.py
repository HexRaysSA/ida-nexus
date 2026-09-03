from __future__ import annotations

import ast
import base64
import binascii
import functools
import hashlib
import inspect
import json
import math
import sys
import textwrap
import threading
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Concatenate,
    Generic,
    Literal,
    ParamSpec,
    Protocol,
    TypeVar,
    cast,
    overload,
)

from .errors import NexusConnectionError
from .models import PythonExecutionResult

if TYPE_CHECKING:
    from ida_domain import Database

P = ParamSpec("P")
R = TypeVar("R")
R_co = TypeVar("R_co", covariant=True)
OperationLabel = str | Callable[[], str | None] | None
RemoteCodec = Literal["typed", "json"]


_CODEC_VERSION = 1
_BYTES_TAG = "$bytes"
_TUPLE_TAG = "$tuple"
_DICT_TAG = "$dict"
_RESERVED_TAGS = frozenset((_BYTES_TAG, _TUPLE_TAG, _DICT_TAG))
_INVOCATION_STATUS = "__remote_ida_status__"
_INVOCATION_VALUE = "__remote_ida_value__"
_STATUS_MISSING_MODULE = "missing_module"
_STATUS_OK = "ok"
_RUNTIME_PREFIX = "__remote_ida_"
_SUPPORTED_VALUES = (
    "None, bool, int, finite float, str, bytes, list, tuple, and dict[str, value]"
)


class RemoteExecutor(Protocol):
    """The structural transport required by remote callables.

    DatabaseHandle satisfies this protocol. Keeping the decorator structural
    makes ordinary fakes sufficient for application and library tests.
    """

    def execute_python(
        self,
        code: str,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
        flush_database: bool = False,
    ) -> PythonExecutionResult: ...


_REMOTE_CODEC_SOURCE = """
import base64 as __remote_ida_base64
import math as __remote_ida_math

__remote_ida_reserved_tags = frozenset(("$bytes", "$tuple", "$dict"))


def __remote_ida_decode(value):
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not __remote_ida_math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is list:
        return [__remote_ida_decode(item) for item in value]
    if value_type is not dict:
        raise TypeError(f"invalid remote_ida encoded value: {value_type.__name__}")

    keys = set(value)
    if keys == {"$bytes"}:
        encoded = value["$bytes"]
        if type(encoded) is not str:
            raise TypeError("invalid remote_ida bytes value")
        return __remote_ida_base64.b64decode(encoded, validate=True)
    if keys == {"$tuple"}:
        items = value["$tuple"]
        if type(items) is not list:
            raise TypeError("invalid remote_ida tuple value")
        return tuple(__remote_ida_decode(item) for item in items)
    if keys == {"$dict"}:
        entries = value["$dict"]
        if type(entries) is not list:
            raise TypeError("invalid remote_ida dictionary value")
        decoded = {}
        for entry in entries:
            if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not str:
                raise TypeError("invalid remote_ida dictionary entry")
            key, item = entry
            if key in decoded:
                raise ValueError(f"duplicate remote_ida dictionary key: {key!r}")
            decoded[key] = __remote_ida_decode(item)
        return decoded
    if keys & __remote_ida_reserved_tags:
        raise ValueError("invalid remote_ida tagged value")
    return {key: __remote_ida_decode(item) for key, item in value.items()}


def __remote_ida_encode(value):
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not __remote_ida_math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is bytes:
        return {"$bytes": __remote_ida_base64.b64encode(value).decode("ascii")}
    if value_type is list:
        return [__remote_ida_encode(item) for item in value]
    if value_type is tuple:
        return {"$tuple": [__remote_ida_encode(item) for item in value]}
    if value_type is dict:
        entries = []
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("remote_ida dictionary keys must be strings")
            entries.append((key, __remote_ida_encode(item)))
        if set(value) & __remote_ida_reserved_tags:
            return {"$dict": [[key, item] for key, item in entries]}
        return {key: item for key, item in entries}
    raise TypeError(
        "remote_ida values must be None, bool, int, finite float, str, bytes, "
        f"list, tuple, and dict[str, value]; got {value_type.__name__}"
    )


def __remote_ida_invoke(db, function_name, pass_database, typed_codec, payload):
    if type(payload) is not dict or payload.get("version") != 1:
        raise ValueError("invalid remote_ida payload")
    if typed_codec:
        args = __remote_ida_decode(payload.get("args"))
        kwargs = __remote_ida_decode(payload.get("kwargs"))
    else:
        args = payload.get("args")
        kwargs = payload.get("kwargs")
    function = globals()[function_name]
    if pass_database:
        value = function(db, *args, **kwargs)
    else:
        value = function(*args, **kwargs)
    if typed_codec:
        return {"version": 1, "value": __remote_ida_encode(value)}
    return value
""".strip()


def _encode_value(value: Any) -> Any:
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is bytes:
        return {_BYTES_TAG: base64.b64encode(value).decode("ascii")}
    if value_type is list:
        return [_encode_value(item) for item in value]
    if value_type is tuple:
        return {_TUPLE_TAG: [_encode_value(item) for item in value]}
    if value_type is dict:
        entries: list[tuple[str, Any]] = []
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("remote_ida dictionary keys must be strings")
            entries.append((key, _encode_value(item)))
        if set(value) & _RESERVED_TAGS:
            return {_DICT_TAG: [[key, item] for key, item in entries]}
        return {key: item for key, item in entries}
    raise TypeError(
        f"remote_ida values must be {_SUPPORTED_VALUES}; got {value_type.__name__}"
    )


def _decode_value(value: Any) -> Any:
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is list:
        return [_decode_value(item) for item in value]
    if value_type is not dict:
        raise TypeError(f"invalid remote_ida encoded value: {value_type.__name__}")

    keys = set(value)
    if keys == {_BYTES_TAG}:
        encoded = value[_BYTES_TAG]
        if type(encoded) is not str:
            raise TypeError("invalid remote_ida bytes value")
        try:
            return base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("invalid remote_ida base64 value") from exc
    if keys == {_TUPLE_TAG}:
        items = value[_TUPLE_TAG]
        if type(items) is not list:
            raise TypeError("invalid remote_ida tuple value")
        return tuple(_decode_value(item) for item in items)
    if keys == {_DICT_TAG}:
        entries = value[_DICT_TAG]
        if type(entries) is not list:
            raise TypeError("invalid remote_ida dictionary value")
        decoded: dict[str, Any] = {}
        for entry in entries:
            if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not str:
                raise TypeError("invalid remote_ida dictionary entry")
            key, item = entry
            if key in decoded:
                raise ValueError(f"duplicate remote_ida dictionary key: {key!r}")
            decoded[key] = _decode_value(item)
        return decoded
    if keys & _RESERVED_TAGS:
        raise ValueError("invalid remote_ida tagged value")
    if any(type(key) is not str for key in value):
        raise TypeError("invalid remote_ida dictionary key")
    return {key: _decode_value(item) for key, item in value.items()}


def _decode_result(value: Any) -> Any:
    if (
        type(value) is not dict
        or set(value) != {"version", "value"}
        or value.get("version") != _CODEC_VERSION
    ):
        raise NexusConnectionError("remote_ida returned an invalid encoded result")
    try:
        return _decode_value(value["value"])
    except (TypeError, ValueError) as exc:
        raise NexusConnectionError(
            "remote_ida returned an invalid encoded result"
        ) from exc


def _validate_options(timeout: float | None, operation_label: OperationLabel) -> None:
    if timeout is not None and (
        isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0
    ):
        raise ValueError("remote_ida timeout must be a positive finite number")
    if operation_label is not None and not (
        callable(operation_label)
        or (isinstance(operation_label, str) and operation_label.strip())
    ):
        raise ValueError(
            "remote_ida operation_label must be non-empty or a zero-argument callable"
        )


def _resolve_operation_label(operation_label: OperationLabel) -> str | None:
    if isinstance(operation_label, str):
        value = operation_label
    elif operation_label is None:
        return None
    else:
        value = operation_label()
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "remote_ida operation_label callable must return a non-empty string or None"
        )
    return value


def _validate_codec(codec: RemoteCodec) -> None:
    if codec not in ("typed", "json"):
        raise ValueError("remote_ida codec must be 'typed' or 'json'")


def _extract_definition(
    function: Callable[..., Any], *, helper: bool = False
) -> tuple[str, str, str, ast.FunctionDef]:
    role = "helper" if helper else "function"
    if not inspect.isfunction(function):
        raise TypeError(f"remote_ida {role}s must be plain Python functions")
    if inspect.iscoroutinefunction(function):
        raise TypeError(f"remote_ida does not support async {role}s")
    if function.__closure__:
        raise TypeError(f"remote_ida {role}s cannot capture nonlocal values")
    try:
        lines, first_line = inspect.getsourcelines(function)
    except (OSError, TypeError) as exc:
        raise TypeError(f"remote_ida could not recover the {role} source") from exc
    source = textwrap.dedent("".join(lines))
    try:
        module = ast.parse(source)
    except SyntaxError as exc:
        raise TypeError(f"remote_ida could not parse the {role} source") from exc
    definitions = [item for item in module.body if isinstance(item, ast.FunctionDef)]
    if len(definitions) != 1 or definitions[0].name != function.__name__:
        raise TypeError(f"remote_ida requires one recoverable {role} definition")
    definition = definitions[0]
    if helper and definition.decorator_list:
        raise TypeError("remote_ida helpers cannot have decorators")
    if not helper and len(definition.decorator_list) > 1:
        raise TypeError("remote_ida cannot be combined with other decorators")
    if function.__name__.startswith(_RUNTIME_PREFIX):
        raise TypeError(f"remote_ida {role} name {function.__name__!r} is reserved")
    definition.decorator_list = []
    ast.fix_missing_locations(definition)
    filename = inspect.getsourcefile(function) or function.__code__.co_filename
    return (
        ast.unparse(definition),
        f"{filename}:{first_line} ({function.__qualname__})",
        function.__name__,
        definition,
    )


def _parameter_shape_from_ast(definition: ast.FunctionDef) -> tuple[Any, ...]:
    args = definition.args

    def default_shape(default: ast.expr | None) -> str | None:
        return (
            None
            if default is None
            else ast.dump(default, annotate_fields=True, include_attributes=False)
        )

    return (
        tuple(item.arg for item in args.posonlyargs),
        tuple(item.arg for item in args.args),
        args.vararg.arg if args.vararg else None,
        tuple(item.arg for item in args.kwonlyargs),
        tuple(default_shape(default) for default in args.kw_defaults),
        args.kwarg.arg if args.kwarg else None,
        tuple(default_shape(default) for default in args.defaults),
    )


def _passes_database(
    parameters: list[inspect.Parameter],
    database: bool | None,
    *,
    role: str,
) -> bool:
    first = parameters[0] if parameters else None
    if database is None:
        return bool(
            first is not None
            and first.name == "db"
            and first.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        )
    if not database:
        return False
    if first is None or first.kind not in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    ):
        raise TypeError(
            f"database-aware {role} must accept a first positional parameter"
        )
    return True


def _stub_is_empty(definition: ast.FunctionDef) -> bool:
    body = list(definition.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    if len(body) != 1:
        return False
    statement = body[0]
    return (
        isinstance(statement, ast.Pass)
        or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        )
        or (
            isinstance(statement, ast.Raise)
            and isinstance(statement.exc, ast.Name)
            and statement.exc.id == "NotImplementedError"
            and statement.cause is None
        )
    )


class _RemoteProgram:
    """A content-addressed module shared by one remote Python interpreter.

    Installation uses the remote interpreter's ``sys.modules``.  The weak
    per-handle map below only avoids redundant installation checks; it does not
    own or isolate the module.
    """

    def __init__(self, source: str, filename: str) -> None:
        self.source = source
        self.filename = filename
        identity = f"{_CODEC_VERSION}\0{_REMOTE_CODEC_SOURCE}\0{source}"
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
        self.module_name = f"_ida_nexus_remote_{digest}"
        self._installed: weakref.WeakKeyDictionary[object, bool] = (
            weakref.WeakKeyDictionary()
        )
        self._lock = threading.Lock()

    def _is_installed(self, handle: RemoteExecutor) -> bool:
        try:
            return bool(self._installed.get(cast(object, handle)))
        except TypeError:
            return False

    def _mark_installed(self, handle: RemoteExecutor) -> None:
        try:
            self._installed[cast(object, handle)] = True
        except TypeError:
            pass

    def ensure(
        self,
        handle: RemoteExecutor,
        *,
        timeout: float | None,
        operation_label: str | None,
        force: bool = False,
    ) -> None:
        with self._lock:
            if not force and self._is_installed(handle):
                return
            runtime_filename = f"{self.filename} [remote_ida runtime]"
            code = f"""import sys as __remote_ida_sys, types as __remote_ida_types
if {self.module_name!r} not in __remote_ida_sys.modules:
    __remote_ida_module = __remote_ida_types.ModuleType({self.module_name!r})
    __remote_ida_module.__file__ = {self.filename!r}
    __remote_ida_sys.modules[{self.module_name!r}] = __remote_ida_module
    try:
        exec(compile({self.source!r}, {self.filename!r}, "exec"), __remote_ida_module.__dict__)
        exec(compile({_REMOTE_CODEC_SOURCE!r}, {runtime_filename!r}, "exec"), __remote_ida_module.__dict__)
    except BaseException:
        __remote_ida_sys.modules.pop({self.module_name!r}, None)
        raise
True
"""
            execution = handle.execute_python(
                code,
                timeout=timeout,
                operation_label=operation_label,
                persist_globals=False,
                filename=self.filename,
            )
            if execution["stdout"]:
                sys.stdout.write(execution["stdout"])
            if execution["stderr"]:
                sys.stderr.write(execution["stderr"])
            self._mark_installed(handle)

    def execute(
        self,
        handle: RemoteExecutor,
        function_name: str,
        pass_database: bool,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        timeout: float | None,
        operation_label: str | None,
        codec: RemoteCodec,
    ) -> Any:
        typed_codec = codec == "typed"
        payload = json.dumps(
            {
                "version": _CODEC_VERSION,
                "args": _encode_value(list(args)) if typed_codec else list(args),
                "kwargs": _encode_value(kwargs) if typed_codec else kwargs,
            },
            allow_nan=False,
            separators=(",", ":"),
        )
        self.ensure(handle, timeout=timeout, operation_label=operation_label)

        def invoke() -> PythonExecutionResult:
            code = f"""import json as __remote_ida_json, sys as __remote_ida_sys
__remote_ida_module = __remote_ida_sys.modules.get({self.module_name!r})
__remote_ida_result = (
    {{{_INVOCATION_STATUS!r}: {_STATUS_MISSING_MODULE!r}}}
    if __remote_ida_module is None
    else {{
        {_INVOCATION_STATUS!r}: {_STATUS_OK!r},
        {_INVOCATION_VALUE!r}: __remote_ida_module.__remote_ida_invoke(
            db,
            {function_name!r},
            {pass_database!r},
            {typed_codec!r},
            __remote_ida_json.loads({payload!r}),
        ),
    }}
)
__remote_ida_result
"""
            return handle.execute_python(
                code,
                timeout=timeout,
                operation_label=operation_label,
                persist_globals=False,
                filename=self.filename,
            )

        def unwrap(execution: PythonExecutionResult) -> tuple[bool, Any]:
            envelope = execution["result"]
            if envelope == {_INVOCATION_STATUS: _STATUS_MISSING_MODULE}:
                return True, None
            if (
                type(envelope) is dict
                and set(envelope) == {_INVOCATION_STATUS, _INVOCATION_VALUE}
                and envelope[_INVOCATION_STATUS] == _STATUS_OK
            ):
                return False, envelope[_INVOCATION_VALUE]
            raise NexusConnectionError(
                "remote_ida returned an invalid invocation envelope"
            )

        execution = invoke()
        missing, result = unwrap(execution)
        if missing:
            self.ensure(
                handle,
                timeout=timeout,
                operation_label=operation_label,
                force=True,
            )
            execution = invoke()
            missing, result = unwrap(execution)
            if missing:
                raise NexusConnectionError(
                    "remote_ida module is unavailable after installation"
                )
        if execution["stdout"]:
            sys.stdout.write(execution["stdout"])
        if execution["stderr"]:
            sys.stderr.write(execution["stderr"])
        return _decode_result(result) if typed_codec else result


class RemoteFunction(Generic[P, R]):
    """A typed callable backed by a process-scoped remote Python module.

    Handles attached to the same IDA process use the same module object, so
    module globals and caches follow normal Python import sharing semantics.
    """

    def __init__(
        self,
        program: _RemoteProgram,
        function_name: str,
        *,
        pass_database: bool,
        timeout: float | None,
        operation_label: OperationLabel,
        codec: RemoteCodec,
        wrapped: Callable[..., Any],
    ) -> None:
        _validate_options(timeout, operation_label)
        _validate_codec(codec)
        self._program = program
        self._function_name = function_name
        self._pass_database = pass_database
        self.timeout = timeout
        self.operation_label = operation_label
        self.codec = codec
        functools.update_wrapper(self, wrapped)
        self.__signature__ = inspect.signature(wrapped)  # type: ignore[attr-defined]

    def __call__(
        self,
        handle: RemoteExecutor,
        /,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        if not callable(getattr(handle, "execute_python", None)):
            raise TypeError(
                "the first argument to a remote function must implement RemoteExecutor"
            )
        label = _resolve_operation_label(self.operation_label)
        return cast(
            R,
            self._program.execute(
                handle,
                self._function_name,
                self._pass_database,
                args,
                kwargs,
                timeout=self.timeout,
                codec=self.codec,
                operation_label=label,
            ),
        )


class _ImplicitDatabaseCallable(Protocol[P, R_co]):
    """A callable whose first positional parameter is statically named ``db``."""

    def __call__(
        self,
        db: Any,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R_co: ...


class RemoteModule:
    """A content-addressed module shared by one remote Python interpreter.

    The installed object lives in the IDA process's ``sys.modules``.  Separate
    database handles attached to that process therefore share its globals,
    caches, mutations, and cache eviction.  Closing one handle does not unload
    the module; changing the source selects a new content-addressed module.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        operation_label: OperationLabel = None,
        codec: RemoteCodec = "typed",
    ) -> None:
        self.path = Path(path)
        self.source = self.path.read_text(encoding="utf-8")
        self.operation_label = operation_label
        self.codec = codec
        _validate_options(None, operation_label)
        _validate_codec(codec)
        try:
            parsed = ast.parse(self.source, filename=str(self.path))
        except SyntaxError as exc:
            raise TypeError(f"remote module is not valid Python: {self.path}") from exc
        self._definitions = {
            item.name: item for item in parsed.body if isinstance(item, ast.FunctionDef)
        }
        reserved = [
            name for name in self._definitions if name.startswith(_RUNTIME_PREFIX)
        ]
        if reserved:
            raise TypeError(f"remote module uses reserved name: {reserved[0]!r}")
        self._program = _RemoteProgram(self.source, str(self.path))

    @overload
    def function(
        self,
        function: _ImplicitDatabaseCallable[P, R],
        /,
        *,
        database: None = None,
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> RemoteFunction[P, R]: ...

    @overload
    def function(
        self,
        function: Callable[P, R],
        /,
        *,
        database: None = None,
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> RemoteFunction[P, R]: ...

    @overload
    def function(
        self,
        function: Callable[Concatenate[Database, P], R],
        /,
        *,
        database: Literal[True],
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> RemoteFunction[P, R]: ...

    @overload
    def function(
        self,
        function: Callable[P, R],
        /,
        *,
        database: Literal[False],
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> RemoteFunction[P, R]: ...

    @overload
    def function(
        self,
        function: None = None,
        /,
        *,
        database: None = None,
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> _AutoRemoteDecorator: ...

    @overload
    def function(
        self,
        function: None = None,
        /,
        *,
        database: Literal[True],
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> Callable[
        [Callable[Concatenate[Database, P], R]],
        RemoteFunction[P, R],
    ]: ...

    @overload
    def function(
        self,
        function: None = None,
        /,
        *,
        database: Literal[False],
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> Callable[[Callable[P, R]], RemoteFunction[P, R]]: ...

    def function(
        self,
        function: Callable[..., Any] | None = None,
        /,
        *,
        database: bool | None = None,
        timeout: float | None = None,
        operation_label: OperationLabel = None,
    ) -> Any:
        def bind(declaration: Callable[..., Any]) -> RemoteFunction[Any, Any]:
            _, _, name, definition = _extract_definition(declaration)
            parameters = list(inspect.signature(declaration).parameters.values())
            inject_database = _passes_database(
                parameters,
                database,
                role="RemoteModule function",
            )
            if not inject_database and not _stub_is_empty(definition):
                raise TypeError(
                    "RemoteModule function declarations must have an empty body"
                )
            implementation = self._definitions.get(name)
            if implementation is None:
                raise TypeError(f"remote module {self.path} has no function {name!r}")
            if _parameter_shape_from_ast(implementation) != _parameter_shape_from_ast(
                definition
            ):
                raise TypeError(
                    f"remote module function {name!r} does not match its declaration"
                )
            remote = RemoteFunction(
                self._program,
                name,
                pass_database=inject_database,
                timeout=timeout,
                operation_label=(
                    operation_label
                    if operation_label is not None
                    else self.operation_label
                ),
                codec=self.codec,
                wrapped=declaration,
            )
            if inject_database:
                remote.__signature__ = inspect.signature(declaration).replace(
                    parameters=parameters[1:]
                )
            return remote

        return bind if function is None else bind(function)


class _AutoRemoteDecorator(Protocol):
    @overload
    def __call__(
        self,
        function: _ImplicitDatabaseCallable[P, R],
        /,
    ) -> RemoteFunction[P, R]: ...

    @overload
    def __call__(self, function: Callable[P, R], /) -> RemoteFunction[P, R]: ...


@overload
def remote_ida(
    function: _ImplicitDatabaseCallable[P, R],
    /,
    *,
    database: None = None,
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> RemoteFunction[P, R]: ...


@overload
def remote_ida(
    function: Callable[P, R],
    /,
    *,
    database: None = None,
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> RemoteFunction[P, R]: ...


@overload
def remote_ida(
    function: Callable[Concatenate[Database, P], R],
    /,
    *,
    database: Literal[True],
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> RemoteFunction[P, R]: ...


@overload
def remote_ida(
    function: Callable[P, R],
    /,
    *,
    database: Literal[False],
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> RemoteFunction[P, R]: ...


@overload
def remote_ida(
    function: None = None,
    /,
    *,
    database: None = None,
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> _AutoRemoteDecorator: ...


@overload
def remote_ida(
    function: None = None,
    /,
    *,
    database: Literal[True],
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> Callable[
    [Callable[Concatenate[Database, P], R]],
    RemoteFunction[P, R],
]: ...


@overload
def remote_ida(
    function: None = None,
    /,
    *,
    database: Literal[False],
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> Callable[[Callable[P, R]], RemoteFunction[P, R]]: ...


def remote_ida(
    function: Callable[..., Any] | None = None,
    /,
    *,
    database: bool | None = None,
    helpers: tuple[Callable[..., Any], ...] = (),
    timeout: float | None = None,
    operation_label: OperationLabel = None,
) -> Any:
    """Declare a typed function that runs in IDA through a RemoteExecutor.

    A first positional-or-keyword parameter named ``db`` receives ida-domain's
    database and disappears from the caller signature. Functions without it run
    exactly as declared, which is ideal for direct IDAPython. ``database=True``
    explicitly injects any first positional parameter; ``database=False``
    disables the naming convention.
    """

    def decorate(selected: Callable[..., Any]) -> RemoteFunction[Any, Any]:
        function_source, filename, function_name, _ = _extract_definition(selected)
        parameters = list(inspect.signature(selected).parameters.values())
        inject_database = _passes_database(
            parameters,
            database,
            role="remote_ida function",
        )
        helper_sources: list[str] = []
        helper_names: set[str] = set()
        for helper in helpers:
            source, _, name, _ = _extract_definition(helper, helper=True)
            if name in helper_names or name == function_name:
                raise TypeError(f"duplicate remote_ida helper name: {name!r}")
            helper_sources.append(source)
            helper_names.add(name)
        source = "from __future__ import annotations\n\n" + "\n\n".join(
            (*helper_sources, function_source)
        )
        program = _RemoteProgram(source, filename)
        remote = RemoteFunction(
            program,
            function_name,
            pass_database=inject_database,
            timeout=timeout,
            operation_label=operation_label,
            codec="typed",
            wrapped=selected,
        )
        if inject_database:
            remote.__signature__ = inspect.signature(selected).replace(
                parameters=parameters[1:]
            )
        return remote

    return decorate if function is None else decorate(function)
