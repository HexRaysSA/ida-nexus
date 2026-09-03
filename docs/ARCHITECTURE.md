# ida-nexus architecture

ida-nexus uses discoverable, shared IDA instances. Each GUI database or
idalib worker exposes the same authenticated loopback HTTP service. MCP servers
attach through client leases rather than owning or terminating IDA processes
directly.

The main data path is:

```text
Claude/Codex MCP config ─┐
Pi/oh-my-pi extension ───┴─> ZeroMCP adapter -> DatabaseManager -> DatabaseHandle
                                                                  │
                                      private registry <──────────┤
                                                                  ├─ SSE lease
                                                                  └─ HTTP RPC
                                                                         │
                                                GUI plugin or idalib worker
                                                                         │
                                                              IDARuntime -> IDA
```

The filesystem registry provides discovery and process liveness; the SSE
connection expresses one client's interest in an already-running database.

## Components

| Component | Responsibility |
|---|---|
| `ida_nexus/plugin.py` | Idempotent, process-wide GUI plugin lifecycle. The first plugin entry point to call `init(owner=...)` owns lifecycle log attribution; all entry points share one service and call `term()` during IDA shutdown. |
| `ida_nexus_plugin.py` | Standalone `plugin_t` entry point that delegates explicitly to `ida_nexus.plugin`. Other plugins can define their own `plugin_t` metadata and use the same lifecycle. |
| `ida_nexus/cli/worker.py` | Opens an executable or IDB with idalib, starts the service, and closes/saves the database when its lifecycle ends. Resolver-spawned workers are managed; directly launched workers are unmanaged unless `--managed` is passed. |
| `ida_nexus/_http.py` | Loopback HTTP/1.1 listener, bearer/host/browser checks, bounded framing and decompression, and streamed responses. |
| `ida_nexus/_server.py` | Nexus routes, instance publication, SSE lease/request accounting, and managed idle shutdown. |
| `ida_nexus/_registry.py` | Canonical identity, cross-platform file locks, atomic records, health classification, and stale-record cleanup. |
| `ida_nexus/_resolver.py` | GUI discovery, expected-IDB resolution, serialized worker spawning, import options, and startup diagnostics. |
| `ida_nexus/handle.py` | Public `DatabaseHandle`, exact instance attachment, SSE lease and IDB-event streams, reusable HTTP RPC, execution, analysis polling/waiting, saving, and exclusive worker shutdown. |
| `ida_nexus/manager.py` | Protocol-agnostic database attachment, local selection and discovery, lease cleanup, and lifecycle events. |
| `ida_nexus/_runtime.py` | Serializes IDA operations onto IDA's main thread and provides the Nexus Python runtime. |
| `ida_nexus/reference.py` | Builds and searches an AST-based reference from the installed ida-domain package and examples without importing ida-domain in the MCP process. |
| `ida_nexus/paths.py` | Resolves the shared state root from the environment and IDA defaults. |
| `ida_nexus/mcp.py` | Reusable ZeroMCP tools and transports, manager composition, error mapping, startup attachment, and semantic session tracing. |
| `ida_nexus/cli/` | Implements the single `ida-nexus` entry point plus thin MCP, dashboard, execution, logs, benchmark, and internal worker command adapters. |
| `ida_nexus/cli/mcp.py` | Parses MCP CLI and agent-hook arguments, then invokes the reusable `ida_nexus.mcp` API. |
| `ida-nexus.ts` | Shared Pi/oh-my-pi extension that starts MCP asynchronously from `session_start`, mirrors its tools with `ida_` names, attaches compatible transcript metadata, and applies host output truncation. Both hosts can enter the session immediately; their lifecycle runners publish late tool registrations before the first model turn. |
| `ida_nexus/cli/dashboard.py` | Renders semantic session traces and linked agent transcripts from the local state directory or a portable log ZIP. |
| `ida_nexus/cli/logs.py` | Builds and validates portable log ZIPs containing selected semantic sessions, linked agent transcripts, operational logs, and a JSON path-mapping TOC. |
| `scripts/migrate_logs.py` | One-shot conversion of pre-0.2 operational/bridge logs into schema-1 semantic sessions. |

## State layout

```text
<state-dir>/
  instances/<record-id>.json       published instance metadata
  instances/<record-id>.lock       held for the instance lifetime
  spawn/<idb-key>.lock             serializes worker creation
  logs/<record-id>.log             idalib worker stdout/stderr
  sessions/<mcp-server-id>.jsonl   semantic MCP/agent trace
```

`<state-dir>` is `IDA_NEXUS_STATE_DIR` when that variable is set. Otherwise
it is `<IDAUSR>/nexus`, where `<IDAUSR>` is the first directory in the
`IDAUSR` environment variable. When `IDAUSR` is unset, IDA's platform default
is used (`~/.idapro` on Unix-like systems or `%APPDATA%/Hex-Rays/IDA Pro` on
Windows).

`record-id` is `<pid>-<six random hex digits>`. The random suffix prevents a
stale Windows lock filename from colliding with a new process after PID reuse
and also correlates a Windows console launcher with its Python child.

The registry record contains the backend (`gui` or `idalib`), PID, endpoint,
authentication token, protocol version, canonical executable and IDB paths,
IDB key, managed flag, and start time. Registry and session directories are
private to the user; records, traces, and worker logs are created with private
permissions.

## Database identity

Real paths stored in records preserve their filesystem spelling. Matching and
spawn serialization use a separate comparison identity:

```python
sha256(identity_key(path).encode("utf-8")).hexdigest()[:16]
```

`identity_key()` expands, absolutizes, and resolves the path. Windows then uses
platform case normalization, while macOS case-folds the value so clients on the
usual case-insensitive volumes agree on one identity. Other platforms preserve
case.

Given an executable, the expected database path is `<executable>.i64`. Given a
path ending in `.i64`, that path is already the database identity.

The executable path remains independently useful: a GUI may have saved its IDB
somewhere unusual. Resolution therefore checks a GUI whose input executable
matches before falling back to the expected IDB path.

## Registration and liveness

Registration order is an invariant:

1. Create and exclusively lock `instances/<record-id>.lock`.
2. Bind and start the HTTP service on `127.0.0.1:0`.
3. Atomically publish `instances/<record-id>.json`.

The fixed grace period protects only the interval between publication and the
first lease. Afterward, a managed worker begins idle shutdown immediately when
its final lease disappears, unless that lease requested a bounded keepalive.
A managed-worker lease may also opt into its own idle timeout. Its deadline is
suspended while lease-owned requests are active and reset after they finish;
expiration releases only that lease, so an indefinite or active peer lease
continues to retain the shared worker.
The watchdog marks the service as draining, closes lease streams and the
listener, and asks the idalib main loop to stop. The registry record and its
lifetime lock remain together while the worker saves/closes the IDB, so a
scanner classifies the stopped owner as `BLOCKED` rather than spawning over it.
Only after the IDB closes does the worker withdraw the record and release the
lock. A plugin unload or process signal follows the same ownership ordering.

The JSON file is discovery metadata; the kernel lock is the liveness authority.
Conceptually, a scanner classifies a parseable record as:

- `READY`: lifetime lock is held, the protocol version is supported, and the
  authenticated health identity matches.
- `BLOCKED`: lifetime lock is held but the protocol version is unsupported,
  health is unavailable, or health does not match the published record.
- `DEAD`: lifetime lock is acquirable; the scanner reaps it instead of returning it.

Only `DEAD` records may be removed. Version mismatches, timeouts,
authentication mismatches, and malformed health responses never justify
spawning over a lock-held instance. A malformed registry record is likewise
removed only when its corresponding lock is acquirable.

A hard-killed process leaves files behind, but the kernel releases its lock.
Any scanner may then reap the JSON and lock files idempotently. Acquirable
orphan instance locks are swept opportunistically. Spawn lock files remain on
disk permanently to avoid split-inode locking races.

## Resolution and worker spawning

`DatabaseHandle.open(path)` performs the following:

1. Canonicalize the requested executable or IDB and scan the registry before
   requiring the path to exist. This permits attachment to an unsaved GUI IDB.
2. For an executable request, find a GUI instance matching its input path.
3. Otherwise find the unique owner of the expected IDB.
4. Return a `READY` owner or report a lock-held `BLOCKED` owner.
5. Acquire `spawn/<idb-key>.lock` and repeat the scan.
6. If still absent, validate the source path and start the
   `ida-nexus worker` as a hidden, detached managed worker.
7. Wait for a record with the expected IDB key and launch identity. Normally the
   PID is sufficient; on Windows the console launcher can hand off to a Python
   child, so the random record suffix is authoritative across both processes.
8. By default, start initial autoanalysis asynchronously only after
   publication. idalib's native `run_auto_analysis=True` path blocks
   database opening, so Nexus opens with it deferred and advances bounded
   analysis slices from a server-owned thread. Each slice uses the normal IDA
   operation dispatcher and then releases it, allowing low-level clients to
   execute between slices. The MCP deliberately still waits on the completion
   barrier before its first execution.

Public `DatabaseOpenOptions` exposes the complete `IdaCommandOptions` import
surface to managed workers: analysis mode, image base, fresh/output database,
compiler, first/second-pass directives, FPP handling, entry point, JIT setting,
kernel log, mouse/plugin/processor options, database compression, debugger and
resource settings, startup script and arguments, loader/member selection, empty
database, Windows directory, segmentation, and debug flags. The worker requires
a 16-byte-aligned byte image base and converts it transparently to IDA's
paragraph-based `-b` value.

An explicit output database resolves by that IDB identity rather than attaching
to a GUI that merely has the same executable open. A fresh-database request
never reuses a live owner. Launch options cannot reconfigure a reused live
instance. When a worker reopens an existing IDB, Nexus
drops source-import options instead of passing invalid loader switches to IDA.
The worker-level `auto_analysis` policy is preserved because it controls whether
analysis starts asynchronously after publication rather than configuring the
loader. These controls belong to `DatabaseOpenOptions`, not the six-tool MCP
surface.

The spawn lock is held until the child becomes ready or fails. Startup waiting
checks `Popen.poll()` without mistaking a successful Windows launcher handoff
for worker exit, and includes the tail of `logs/<record-id>.log` when startup
fails, so import, licensing, and IDA load failures are reported directly. If a
managed worker crosses its zero-lease shutdown boundary between resolution and
the SSE handshake, `DatabaseHandle.open()` resolves once more before failing.

IDA itself remains the final protection against an unregistered IDA process or
a race with an independently opened GUI.

## HTTP and IDA execution

Each per-database Nexus service is bound to loopback, requires the bearer
token from the private registry record, validates `Host`, and rejects
browser-originated requests. Request framing and content encoding are strict,
and both encoded and decompressed body sizes are bounded.

Important routes are:

| Route | Purpose |
|---|---|
| `GET /health` | Authenticated record identity and liveness probe. |
| `GET /health?sse=1` | Persistent client lease with periodic heartbeat, optional post-release keepalive, and optional per-lease idle timeout. |
| `GET /idb_events` | Structured database-operation events after initial autoanalysis finishes. |
| `POST /release_lease` | Idempotently release one identified client lease. |
| `POST /execute_python` | Execute Nexus Python against the open database. |
| `POST /cancel_operation` | Cooperatively cancel one lease-owned operation without releasing the database handle. |
| `POST /save_database` | Explicitly save a GUI or idalib database. |
| `POST /shutdown_database` | Shut down an exclusively leased managed idalib worker, saving or discarding changes. |
| `GET /poll_autoanalysis` | Observe initial IDA autoanalysis without enabling or advancing it. |
| `GET` or `POST /wait_autoanalysis` | Wait for autoanalysis; POST accepts a timeout. |

Closing a client handle uses a separate control connection to release only its
identified lease, then closes its local connections. A separate low-level
shutdown route is available only for a managed idalib worker whose requesting
lease is exclusive; GUI and shared instances reject it. Ordinary RPCs carry
that lease identity so orphaned execution can be cancelled. The reusable
HTTP/1.1 RPC connection is replaced before the server's idle timeout. The listener uses the platform's maximum
backlog and a small prewarmed cache of reusable daemon handler threads; this
avoids paying Windows thread-start scheduling latency on every fresh loopback
connection while still growing for long-lived SSE leases. A failed operation
POST is never retried because its execution status may be ambiguous.

These guarantees apply to the per-database API. The optional ZeroMCP HTTP
transport and dashboard have no built-in authentication; both default to local
usage and warn when explicitly bound beyond loopback. Stdio is the normal MCP
transport.

`IDARuntime` serializes operations and dispatches them through
`ida_kernwin.execute_sync`. Worker background autoanalysis uses bounded
`auto_make_step()` slices, releasing that serialization point between slices;
this mirrors the GUI's idle-driven analysis and preserves the low-level API's
ability to execute while initial analysis is still running. An explicit
`wait_autoanalysis()` remains a blocking drain, and the MCP intentionally uses
that barrier before model-authored execution. The current ida-domain `Database` is available
globally as `db`, alongside the imported `ida_domain` package. Ordinary
statements execute once, and a single or trailing expression becomes the
result. As an alternative, code without a trailing
expression may define `run(db)`, `execute(db)`, or `main(db)` for automatic
invocation. Native IDA cancellation and a targeted asynchronous CPython
exception interrupt both native work and pure-Python loops without installing a
per-line or per-opcode trace hook. Before compilation, Nexus gives every
submitted exception handler a higher-priority cancellation branch so bare
`except` and `except BaseException` clauses cannot consume that private
interrupt. Generation checks prevent a late timeout from poisoning the next
operation.

## Protocol contract and versioning

`PROTOCOL_VERSION` is currently `8`. It is an exact compatibility version for
the private discovery registry and per-database HTTP API. There is no downgrade
or highest-common-version negotiation: a scanner whose local version differs
from a lock-held record marks that owner `BLOCKED` before probing HTTP. This is
deliberate—starting a replacement could corrupt an IDB already owned by a peer
that the scanner does not understand.

Protocol version 8 consists of the following interoperable contracts.

### Discovery contract

A published `instances/<record-id>.json` record has these required fields:

| Fields | Contract |
|---|---|
| `record_id` | `<pid>-<six lowercase hex digits>` and equal to the filename stem. |
| `backend` | `gui` or `idalib`. |
| `pid`, `port` | Positive process ID and loopback TCP port. |
| `token` | Bearer secret used by every per-database HTTP request. |
| `version` | Exact Nexus protocol version. |
| `idb_path`, `exe_path` | Case-preserving canonical paths; the executable path may be empty. |
| `idb_key` | The 16-hex-digit identity described in **Database identity**. |
| `managed` | Whether zero leases trigger worker shutdown. |
| `started_at` | Unix start timestamp. |

The matching lifetime lock, atomic publication order, IDB identity algorithm,
spawn-lock naming, and `READY`/`BLOCKED`/`DEAD` rules are part of this discovery
contract. Readers require all fields above but ignore unknown additive fields.

`GET /health` must return `status: "ok"` plus the record's `record_id`,
`backend`, `pid`, `version`, `idb_path`, `idb_key`, `exe_path`, `managed`, and
`started_at`. The port and token are not echoed. A client compares every known
field but ignores unknown additive health fields.

### Wire and lifecycle contract

All non-streaming request bodies are JSON objects. The operation contracts are:

| Route | Request and response contract |
|---|---|
| `GET /health` | Raw health identity object described above. |
| `GET /health?sse=1` | `text/event-stream`; accepts `lease_id`, bounded post-release `keepalive`, and optional positive `idle_timeout` query values. It emits one initial `health` event and heartbeat comments. A timed managed-idalib lease emits `lease_expired` with its timeout before disconnecting when possible. |
| `GET /idb_events` | `text/event-stream`; accepts subscribers immediately but installs its structured IDB hook only after initial autoanalysis completes. Each `idb_changed` payload is one event containing `event_name`, nanosecond Unix `timestamp`, monotonically increasing `revision`, event-specific fields, and nullable `origin_id`, `operation_id`, and `operation_label`. `origin_id` is an opaque, one-way-derived identity for the executing lease; it supports handle-local event recognition without disclosing the control-capable `lease_id`. The GUI plugin uses `IDA GUI` as the operation label outside `execute_python()` calls, covering direct UI actions and GUI-process background work. The hook is removed after the final subscriber disconnects. A subscriber that exceeds its bounded queue is disconnected rather than receiving an incomplete history. |
| `POST /release_lease` | `{lease_id}`; idempotently detaches that lease and returns `{"released":true,"shutdown_pending":bool}`. A true `shutdown_pending` commits final zero-keepalive managed shutdown so the client may wait for the lifetime lock to be released. |
| `POST /execute_python` | `{code, timeout?, lease_id?, operation_id?, operation_label?, persist_globals?, filename?}`; success is `{"ok":true,"result":{"result":...,"stdout":...,"stderr":...}}`. The optional operation label is opaque display text containing 1 to 1024 characters and at least one non-whitespace character. Persistence defaults to false and requires an active lease. Execution does not implicitly wait for autoanalysis. |
| `POST /cancel_operation` | `{lease_id, operation_id}`; success is `{"ok":true,"result":{"cancelled":bool}}`. Cancellation is lease-scoped and preserves the handle. |
| `POST /save_database` | `{lease_id?}`; success is `{"ok":true,"result":{"saved":true,"idb_path":...}}`. |
| `POST /shutdown_database` | `{lease_id, save}`; the active lease must be exclusive and own a managed idalib worker. Success is `{"ok":true,"result":{"shutting_down":true,"save":bool}}`, after which teardown uses `Database.close(save=save)`. |
| `GET /poll_autoanalysis` | Raw `{status, complete}` analysis object; accepts an optional `lease_id` query value so handle polling counts as lease activity. Observing it never enables or advances analysis. `status` is `running`, `complete`, or `disabled`. A persistently disabled GUI settles the barrier as `disabled` with `complete: true`; temporary GUI-action suspension does not. |
| `GET` or `POST /wait_autoanalysis` | The same raw analysis object; POST accepts optional `timeout`, `lease_id`, and `operation_id` fields. An omitted timeout waits without a deadline. An explicit wait advances a `disabled` barrier by temporarily enabling the runtime analyzer without changing the persistent GUI setting. |

Request-owned cancellation requires registry protocol version 3. Version 4 adds
opt-in lease-scoped persistent Python namespaces. Version 5 requires execution
results to be directly JSON-serializable and adds exclusive managed-worker
shutdown. Version 6 reports when explicit lease release commits final managed
shutdown. Version 7 distinguishes a persistently disabled GUI autoanalyzer from
temporary runtime suspension. Version 8 adds opt-in, server-enforced per-lease
idle expiration for managed idalib workers. These exact versions prevent a new client from
silently attaching to a GUI plugin or worker that cannot provide the lifecycle
and execution semantics on which it relies.

Operation failures use a non-2xx status and, once application dispatch has
begun, `{"ok":false,"error":{"code":...,"message":...}}`; additional error
details are optional. Authentication, framing, and unknown-route failures may
use simpler non-2xx JSON bodies, so clients must not assume a structured error
for every rejection. Lease release has only lease-scoped authority. Shutdown
requires an exclusive active lease on a managed worker and is unavailable for
GUI instances. Clients must not retry an operation POST whose execution outcome
is unknown.

The execution rules (`db`/`ida_domain`, trailing-expression results, optional
entry functions, strict JSON-compatible results, output capture, and serialized
IDA execution) and the SSE-driven managed shutdown semantics are
also protocol behavior because clients observe them. Execution uses a fresh
namespace by default. A stateless leased execution first discards any namespace
previously retained by that lease. When `persist_globals` is true, imports,
assignments, and definitions remain visible to later opted-in executions through
the same lease. Runtime-owned globals are refreshed, previous
`run`/`execute`/`main` functions are not invoked again implicitly, and `result`
remains a consumed per-call output slot rather than durable state. Results are
encoded with the standard C-backed JSON encoder after leaving IDA's main thread.
They must already be JSON-compatible; unsupported Python or IDA objects and
non-finite floats fail with `invalid_result` rather than being coerced into
lossy strings or containers.

The typed `remote_ida` and `RemoteModule` layer deliberately has a different
lifetime from `persist_globals`. It installs content-addressed modules in the
remote interpreter's `sys.modules`, following ordinary Python import semantics.
Every handle attached to the same IDA process therefore observes the same module
object, globals, caches, mutations, and cache eviction. A local per-handle
installation marker only suppresses redundant checks; it is not an ownership or
isolation boundary. Lease release does not unload these modules. A source change
selects a new module name, and normal interpreter teardown releases all versions.

### When to bump the version

The protocol version is not the package or release version. Readers and writers
should preserve it for:

- implementation, performance, timeout, or heartbeat changes that retain the
  behavior above;
- new optional registry, health, request, response, or error-detail fields;
- new optional routes that old peers may safely reject;
- changes to MCP tools, worker CLI options, semantic traces, dashboard output,
  or agent integrations. The trace format has its own `schema` field, while MCP
  has its own protocol negotiation.

Bump `PROTOCOL_VERSION` only when an existing peer could no longer interoperate
safely—for example, when removing or changing the type or meaning
of a required registry field; changing path identity, lock ownership, auth, or
lease semantics; or incompatibly changing an existing route's method, request,
response, error, execution, or save behavior. A feature that must be relied on
across mixed installations needs either an optional capability probe or a
protocol bump; it must not silently reinterpret an existing field.

## Shared leases and managed shutdown

Each `DatabaseHandle` owns one authenticated SSE lease connection in addition
to its on-demand RPC connection. A handle is indefinite by default; a positive
`idle_timeout` opts only that handle into managed-worker idle expiration. GUI
and unmanaged-idalib handles ignore the option. `subscribe_idb_events()` opens an optional,
closeable SSE iterator whose revisions signal consumers to refresh cached IDB
data. Multiple handles, MCP servers, and agents may share the same instance.
Closing one handle closes only its own connections and event subscriptions.
Each handle exposes its opaque `event_origin_id`; `owns_event()` compares it to
an event's optional `origin_id`. The origin is derived from the private lease ID,
so it remains stable for the handle lifetime without revealing the identifier
used for cancellation, release, or persistent namespace ownership.

The server emits heartbeat comments so crashed clients are detected when the
next write fails. A fixed startup grace protects the race between worker
publication and its first lease. Established leases default to zero keepalive,
so their explicit release or detected disappearance starts shutdown without an
additional grace period. Low-level clients may request a bounded keepalive when
opening a lease to retain an idle worker for repeated short-lived invocations.
`keepalive` starts only after release; `idle_timeout` instead determines when an
otherwise-live managed-worker lease releases itself. Lease heartbeats, registry
probes, other clients, event streams, and background analysis do not reset that
deadline. A lease-owned request suspends expiration until it finishes and then
starts a fresh timeout period.

Each RPC carries its owning lease identity. An execution that explicitly opts
into persistence uses a lease-scoped global namespace, giving one handle
REPL-like imports, variables, and definitions without exposing them to other
handles or agents. Stateless execution remains the default and resets any
persistent state previously associated with its lease. Adapters may reserve
private names in the persistent namespace; `ida-domain-multiplex` uses one such
name for its process-bound proxy table. The
runtime clears the namespace on explicit release or SSE disconnection, breaking
function/global cycles so native objects are released promptly. Unleased
requests continue to use fresh execution globals. Releasing a lease cancels its
orphaned operation before session cleanup; cancellation is cooperative and the
worker waits only for safe unwinding, not successful completion. Once no leases
remain and the final lease's keepalive has expired, the worker stops serving,
returns to the idalib main thread, saves/closes the IDB, then withdraws its
registry record and exits.

The `ida-nexus exec` adapter supplies an operation label for every execution:
`REPL: interactive`, `REPL: stdin`, `REPL: command`, or
`REPL: script <absolute path>`. Script labels retain the path suffix when the
1024-character protocol limit requires truncation.

A new lease before shutdown begins cancels pending shutdown. GUI instances are
unmanaged and ignore zero leases.

Worker lifetime follows the explicit SSE lease, not the incidental lifetime of
a reusable RPC socket or a fragile client-maintained process refcount. Client
crashes and `kill -9` are handled by socket and kernel-lock cleanup.

## Crash-safe database reopening

IDA holds the unpacked database's `.id0` open under an OS-level denial/exclusive
lock for the session lifetime. Nexus probes that lock before spawning over a
database not represented in the registry. While holding the probe lock, it
reads the B-tree `isTreeOpen` byte: a dirty unlocked `.id0` identifies crash
leftovers; a locked `.id0` identifies a live IDA even when that process has no
Nexus plugin.

Recovery never reconnects an existing handle and never retries an ambiguous
Python POST. The failed handle reports `DatabaseCrashedError` when the dirty
state is observable. Consumers may call `probe_database_state()` and explicitly
open a replacement. An unpacked-only crash is opened without the destructive
`-c -o` import path, repaired by IDA, and immediately packed. When a packed base
also exists, unpacked components are durably copied to `<idb>.crash-*` before
IDA restores the packed base. Indeterminate file states and live foreign owners
fail closed.

`flush_database=True` on `/execute_python` makes a best-effort
`ida_loader.flush_buffers()` call inside the same IDA main-thread operation
immediately before user code. License configurations that reject flushing do
not block execution. A successful flush does not pack the IDB and does not
cover mutations made later by that same crashing snippet. The option defaults
to false for the public Python API and CLI. The MCP tool deliberately does not
expose this policy decision to the model.


## MCP model

The MCP server keeps MCP-local opaque `instance_id` values mapped to
`DatabaseHandle` objects. Reopening the same registry record within one MCP
server reuses the existing local session and retains only one lease. Separate
MCP servers retain independent leases. Registry discovery lets
`list_databases()` also report GUI and idalib instances that this MCP server
has not yet attached to; local handles are annotated with their `instance_id`
and current-target state. If a lease connection dies, its MCP-local
`instance_id` is invalidated immediately. Nexus never silently reconnects
or replaces the database; the agent must discover and open it again.

Tools are:

| Tool | Behavior |
|---|---|
| `reference(query)` | Search the installed ida-domain API reference. |
| `open_database(path, set_current=True)` | Attach to a GUI or shared managed worker. |
| `execute_python(code, instance_id=None, timeout=360, filename=None)` | Wait without a deadline for initial autoanalysis once through a separate handle request, then execute Python against the selected handle with the numeric execution-only timeout. Flush policy is not model-controlled. |
| `list_databases()` | Discover registered instances and identify this MCP server's handles. |
| `save_database(instance_id=None)` | Explicitly save the selected database. |
| `close_database(instance_id=None)` | Release this MCP server's handle. If that commits final managed shutdown, wait up to 305 seconds for the IDB close and lifetime-lock release; it is not a global close. |

`--database` schedules a startup attachment without blocking MCP
initialization; an operation that needs the current target waits for that
startup attempt. The server normally runs over stdio, with an opt-in reusable
ZeroMCP HTTP transport. HTTP can run in background embedding mode or unattended
foreground mode. A host may supply a `DatabaseManager` subclass and constructor
arguments, register traced tools with `ida_nexus.mcp.tool`, and select a native
ZeroMCP HTTP path prefix without importing CLI implementation details. The Pi
extension is an MCP client adapter rather than a second implementation of these tools.
The MCP adapter explicitly applies the initial
analysis policy before calling the session manager's `execute_python`; the
upstream route and handle execution method remain independent of analysis. The
initial analysis wait is unbounded and does not consume the MCP tool's separate
execution timeout. Stdio uses ZeroMCP's concurrent async dispatcher so MCP
`notifications/cancelled` can arrive during analysis or execution. The async
tool sends a separate operation-id-scoped cancellation request and waits for
IDA to unwind safely before abandoning the MCP request without a response.

On stdio EOF, SIGINT, SIGTERM, or normal interpreter exit, the MCP server
releases all handles. Other agents continue uninterrupted. If the released
lease was the last lease on a managed worker, that worker performs its own
shutdown. MCP and direct library leases remain indefinite unless they opt in.
The MCP accepts `--idle-timeout` or `IDA_NEXUS_MCP_IDLE_TIMEOUT`; zero disables
idle release explicitly.

## Semantic sessions and agent metadata

The MCP server writes one session-oriented JSONL trace to:

```text
<state-dir>/sessions/<mcp-server-id>.jsonl
```

Every record includes schema version, timestamp, MCP server ID, MCP PID, and an
event. `mcp_started` records the optional `--agent` label, while
`mcp_initialized` records the MCP client's `clientInfo` and `_meta`. Tool
activity is represented by `tool_call`, `tool_result`, and `tool_error`, paired
by `call_id`. Database binding events contain MCP-local and registry identity,
including the worker operational log path, and inherit the active `call_id`
when emitted during a tool invocation.

Agent integrations attach transcript paths as hidden `_meta` fields using the
`<agent-kind>_session_path` convention (for example, `omp_session_path`). The
MCP adapter promotes those fields into request metadata and removes them from
public tool arguments. Each tool event records the applicable `nexus_id` and
agent transcript path under `session`. The optional MCP `--agent` value is a
process-level display and operation label; transcript correlation uses the
request metadata because one MCP process can serve multiple agent sessions and
agent kinds. This also supports several agents sharing one IDA worker.

Semantic tracing remains at the MCP layer because only that layer can observe
`reference`, list operations, resolution failures, and agent metadata. Worker
logs are operational and correlate through `record_id` and timestamps.

The dashboard reads the semantic session schema. It correlates calls and
results by ID while rendering each at its own timestamp, links enclosed legacy
database events to their unambiguous call interval, renders executed Python and
reference output, distinguishes MCP results and model-facing errors from
internal diagnostic metadata, lists all database targets and best-effort
transcript model names, and interleaves non-IDA activity from referenced agent
transcripts. The log exporter and dashboard recognize any agent kind that uses
the `<agent-kind>_session_path` metadata convention. Timestamped agent records
outside the recognized Claude, Codex, and Pi event shapes are retained as
collapsed raw-JSON fallback events instead of being silently discarded. The
dashboard can also auto-detect the benchmark run
layout, select Pi's active transcript branch, summarize available token/cost
data, and export a self-contained session page. Its `/agent` route serves only
transcript paths referenced by discoverable semantic sessions.

`ida-nexus logs` packages all local semantic sessions by default, or only
explicitly named session files, together with every available linked agent
transcript and every file under the operational `logs/` directory. The root
`ida-nexus-logs.json` TOC records schema/version, checksums,
original-to-archive path mappings, per-session transcript references, and
missing references for semantic and agent sessions. Operational files are
preserved under `logs/` without TOC entries. The dashboard validates checksums
and extracts only TOC-listed session members into a private temporary directory
when started with `--archive`; unresolved archive references are never read
from the receiving machine's filesystem.

## Legacy migration

`scripts/migrate_logs.py` reads transitional schema-1 traces from `logs/mcp/` and older
bridge JSONL files from `logs/`, then writes normalized session files under
`sessions/`. It never modifies source logs, sanitizes destination names, and
reports malformed, unknown, or unattributable records instead of silently
placing them in the permanent schema. Known `bridge_output` noise is counted
and intentionally discarded from migrated sessions.

## Failure behavior

| Failure | Result |
|---|---|
| MCP/client exits cleanly | Its leases close; other clients continue. |
| MCP/client is killed | Kernel closes sockets; heartbeat observes the loss. |
| Managed worker is killed | Lifetime lock releases; stale metadata is reaped on scan. |
| Protocol version differs | Instance is `BLOCKED` before HTTP probing; no replacement is spawned. |
| Health times out | Instance is `BLOCKED`; no replacement is spawned. |
| Worker exits during startup | Resolver raises with process status and log tail. |
| Worker begins idle shutdown before the first lease | The handle resolves and attempts attachment once more. |
| GUI or worker disappears after opening | Its `instance_id` is invalidated; the next operation tells the agent to list and open again. |
| RPC connection fails during a POST | The connection is discarded, but the operation is not retried because it may already have executed. |
| Response contains an IDA error | Structured code, status, details, and traceback reach MCP tracing. |

The architecture deliberately favors harmless stale files and reloadable
workers over cross-client shutdown authority or ownership bookkeeping.
