# IDA Nexus

⚠️ Experimental prerelease ⚠️

IDA Nexus allows multiple clients to seamlessly share and operate on IDA databases.

Consumers of the IDA Nexus library will transparently discover and share databases
already open in the IDA GUI, or start a managed idalib worker when necessary.
The goal is to enable an ecosystem where many tools can freely operate on a single IDB together.
To achieve this, IDA Nexus exposes a compact Python execution surface with the
[`ida-domain`](https://github.com/HexRaysSA/ida-domain) API available.

## GUI

To support IDA GUI instances when using IDA Nexus, install the plugin:

```bash
uvx ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus
```

_Note_: Without the GUI plugin, IDA Nexus will only work headlessly.

## MCP

See the [Official Hex-Rays IDA MCP Server](https://github.com/HexRaysSA/ida-mcp#installation)
for more information on installing the MCP.

## CLI

```bash
# MCP server (stdio/http)
uvx ida-nexus mcp --agent=my-agent

# Inspect MCP session logs
uvx ida-nexus dashboard --open

# Export MCP session logs to ZIP
uvx ida-nexus logs

# IDA Domain API reference
uvx ida-nexus reference "decompile function"

# Execute Python against an IDB (command, script, repl)
uvx ida-nexus python tests/crackme03/elf -c 'db.functions.get_all()'
```

`python` labels resulting database events by input mode: `REPL: interactive` for
a terminal session, `REPL: stdin` for piped input, `REPL: command` for `-c`,
and `REPL: script <absolute path>` for a script file. These labels are restored
between executions like every other `execute_python()` provenance label.

Run `uvx ida-nexus COMMAND --help` for command-specific options.

## Python Package (Developers)

You can build on `ida-nexus` as a library and reuse the database management
functionality. Doing so will transparently allow other `ida-nexus` users
to use IDBs concurrently and work together.

### Example scenarios

Below are a few scenarios enabled by the `ida-nexus` library:

- You have an executable open in the IDA GUI and would like to use the MCP without closing IDA.
- Your main agent spawns 5 subagents to work on different parts of the IDB concurrently.
- A headless database is created by the MCP, you want to access it with a CLI tool.
- You develop a web application to look at all the open IDA databases at once.

### API

`DatabaseHandle` is the primary API. One handle owns one lease on an exact GUI
or idalib database; closing it releases only that lease.

```python
from ida_nexus import DatabaseHandle, DatabaseOpenOptions

options = DatabaseOpenOptions(
    startup_timeout=300,
    processor="arm",
    image_base=0x08000000,
)
with DatabaseHandle.open("firmware.bin", options=options) as handle:
    handle.wait_autoanalysis()
    execution = handle.execute_python(
        "len(list(db.functions.get_all()))",
        timeout=60,
    )
    print(execution["result"])
```

IDA import settings in `DatabaseOpenOptions` apply only when Nexus imports a
new source file. They do not reconfigure a reused GUI, worker, or existing IDB.
For a newly spawned worker, `auto_analysis=True` starts sliced analysis
after the worker is published. Low-level `execute_python()` calls can run
between slices, while `wait_autoanalysis()` explicitly drains the same lifecycle.
The MCP intentionally waits before model-authored execution.
A persistently disabled GUI reports an immediately usable `disabled` analysis
status without confusing IDA's temporary suspension during GUI actions.
`execute_python()` is stateless by default; pass `persist_globals=True` to keep
a lease-scoped Python namespace between calls.

### Crash detection and recovery

`execute_python()` never retries after a connection failure because the code may
already have mutated the IDB. Pass `flush_database=True` to flush the unpacked
`.id0`/`.id1` buffers immediately before and after the snippet:

```python
from ida_nexus import DatabaseCrashedError

try:
    handle.execute_python(risky_code, flush_database=True)
except DatabaseCrashedError as error:
    print(error.database_state)
```

These are best-effort buffer flushes, not packed `.i64` saves. License
configurations that reject flushing do not block Python execution. The first
flush protects earlier work; the second protects changes made by the snippet
when execution returns or raises a Python exception. A native process crash
cannot run the second flush. The public Python API, HTTP endpoint, and
`ida-nexus python --flush-database` expose this policy; the MCP tool does not let
the model select it.

`probe_database_state(path)` combines the `.id0` OS lock with its B-tree
`isTreeOpen` byte and reports `missing`, `packed`, `in_use`, `crashed`,
`unpacked`, or `unknown`. A failed lease is permanent: close the old handle and
open a new one. `DatabaseHandle.recovery` and `DatabaseManager.open_database()`'s
`recovery` result then report:

| Result | Behavior |
|---|---|
| `none` | No crashed database was observed. |
| `repaired` | Only dirty unpacked files existed. IDA repaired them and Nexus immediately created a packed base. |
| `restored` | A packed base existed. Nexus preserved the dirty unpacked files in an adjacent `<idb>.crash-*` directory, then restored the packed base. Changes newer than that packed base are not active automatically. |

Unexpected disconnection records `database_disconnected` at warning level in
the semantic session trace. Stdio MCP clients also receive a ZeroMCP
`notifications/message` warning from logger `ida_nexus.database`. Its structured
data contains `event`, `message`, `instance_id`, `reason`, `target`,
`database_state`, and `recovery_required`. Streamable HTTP does not currently
support MCP logging notifications; the semantic warning record is still written.

An unregistered live IDA holding the `.id0` lock causes `DatabaseBusyError`.
Missing `.id0`, malformed headers, partial component sets, and custom output
paths that cannot be recovered safely cause `DatabaseOpenError` rather than a
destructive fresh import. If IDA itself cannot repair an unpacked-only database,
worker startup fails and the unpacked files remain available for manual
recovery. Advisory file locking can be unreliable on NFS/SMB; an unlocked probe
on network storage is not proof that no live owner exists.

Library leases are indefinite by default. A client that wants its own managed
idalib lease released after inactivity can set `idle_timeout` without affecting
other leases on the shared worker:

```python
options = DatabaseOpenOptions(idle_timeout=900)
```

The deadline is suspended while that lease has an active request and restarts
when the request finishes. GUI and unmanaged-idalib handles ignore it.
`keepalive` is separate: it delays worker shutdown only after a lease is released.
MCP leases are also indefinite by default. Opt into idle release with
`ida-nexus mcp --idle-timeout 900` or set
`IDA_NEXUS_MCP_IDLE_TIMEOUT=900`; passing zero explicitly disables it.

Database changes are available as a closeable, blocking iterator. Each item is
one structured IDB hook event with a monotonically increasing `revision`, a
nanosecond Unix `timestamp`, the `operation_id` and optional untrusted
`operation_label` active when IDA emitted it, and a nullable opaque `origin_id`.
The origin is derived from the producing handle's private lease without exposing
that control-capable lease ID. The GUI plugin labels events outside an
`execute_python()` operation as `IDA GUI`; its background analysis and direct UI
actions share that source:

```python
with handle.subscribe_idb_events() as events:
    for event in events:
        print(
            event["event_name"],
            event["revision"],
            event["operation_id"],
            event["operation_label"],
            handle.owns_event(event),
        )
```

`handle.owns_event(event)` identifies changes made through that handle without
requiring the consumer to generate or retain operation IDs. `operation_id`
remains available when correlation with one specific execution is useful.

Each subscriber buffers at most 4096 events. A subscriber that falls behind is
disconnected rather than receiving an incomplete history. The subscription can
be opened before autoanalysis completes; hooks are installed after initial
autoanalysis and removed when the final subscriber disconnects.

`@remote_ida` turns an ordinary typed function into a synchronous remote
callable. It can use IDAPython directly; no `db` parameter is required:

```python
from ida_nexus import DatabaseHandle, remote_ida


@remote_ida(operation_label=lambda: f"IDA TUI: {active_user()}")
def screen_address() -> int:
    import ida_kernwin

    return int(ida_kernwin.get_screen_ea())


with DatabaseHandle.open("firmware.bin") as handle:
    address = screen_address(handle)
```

When the first parameter is named `db`, ida-domain's database is injected
automatically and removed from the caller signature:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ida_domain import Database


@remote_ida(timeout=10, operation_label="firmware browser")
def read_bytes(db: Database, address: int, size: int) -> bytes:
    return db.bytes.get_bytes_at(address, size) or b""


header = read_bytes(handle, 0x401000, 16)
```

Use `database=True` to inject an unusually named first positional parameter, or
`database=False` to treat a parameter named `db` as ordinary caller data. The
explicit flag is also the static typing discriminator for those overrides.

String labels and zero-argument label callables are supported. Callables are
evaluated once per invocation, so a `ContextVar` or application user/session
provider can produce labels such as `IDA TUI: alice`; installation and execution
of that call receive the same resolved label.

The first call installs a content-addressed module through any object satisfying
`RemoteExecutor`; later calls send only encoded arguments and a short invocation.
`RemoteExecutor` is structural, so tests can use an ordinary fake with
`execute_python()`. Remote functions must be synchronous, source-backed `def`
functions without closures or stacked decorators. Explicit `helpers=(...)`
bundle reusable plain functions into the same installed module.

Large or stateful implementations belong in a real Python module, not a string.
`RemoteModule` reads and content-hashes that file, installs it once per IDA
Python interpreter, keeps its module globals and caches alive, and validates
declarations against the implementation signature:

```python
from ida_nexus import RemoteModule

tools = RemoteModule("remote_tools.py", operation_label="firmware browser")


@tools.function(timeout=15)
def decompile(address: str, include_addresses: bool = True) -> dict: ...


result = decompile(handle, "0x401000")
```

`RemoteModule.function()` follows the same `db` naming convention and supports
the same explicit `database=True` and `database=False` decorator-factory forms.
Declarations for ordinary module functions have an empty body; database-aware
functions may be their real import-safe implementation. Parameter names, kinds,
and default expressions are checked against the implementation while the
application imports.

Installed remote modules use normal Python `sys.modules` semantics. Two handles
attached to the same IDA process share the module object, including mutable
globals, caches, and cache eviction. The client-side per-handle record is only an
installation-check optimization; closing a handle does not unload the module.
Use lease-scoped `persist_globals=True` execution instead when state must be
private to one handle.

The default `codec="typed"` preserves bytes and tuples. A module whose boundary
is guaranteed JSON-native can use `codec="json"` to return large dictionaries
and lists without an additional Python-level value walk.

Arguments and results may recursively contain `None`, booleans, integers, finite
floats, strings, bytes, lists, tuples, and string-keyed dictionaries. Unsupported
values fail at the call boundary rather than silently degrading to strings.

Discovery returns public instance descriptors that support exact attachment:

```python
from ida_nexus import DatabaseHandle, InstanceState, discover_databases

ready = [
    item.instance for item in discover_databases() if item.state is InstanceState.READY
]
with DatabaseHandle.attach(ready[0]) as handle:
    print(handle.instance.record_id, handle.instance.idb_path)
```

`find_database_owner()` and `wait_database_released()` support clients that must
safely replace an executable or IDB. `DatabaseManager` is the secondary API for
MCP-style adapters that manage several handles and a current target. All
supported Python names are exported directly from `ida_nexus`; underscore
modules and non-exported implementation modules are private.
See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for more details.
