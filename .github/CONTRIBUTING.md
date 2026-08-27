# Contributing

⚠️ **We do not accept pull requests at this time.** ⚠️

If you run into problems with the installation, feel free to open an issue!

## MCP tools

- `reference(query)` - search the installed ida-domain API reference.
- `open_database(path, set_current=True)` - attach to a GUI database or shared idalib worker.
- `execute_python(code, instance_id=None, timeout=360)` - wait without a deadline for initial autoanalysis on the first execution for an attached database, then run Python with the requested execution timeout and return its result, stdout, and stderr.
- `list_databases()` - discover all registered GUI and idalib instances and identify this MCP server's active handles.
- `save_database(instance_id=None)` - explicitly save a database.
- `close_database(instance_id=None)` - release this MCP server's handle and lease.

The intended flow is `open_database` → `reference` → `execute_python`.
Inside `execute_python`, `db` is the current `ida-domain` `Database`; both
`db` and `ida_domain` are available globally. Ordinary Python statements are
accepted, a single or trailing expression becomes the result, and
`def run(db): ...` remains
available for function-style code.

`close_database` is not a global shutdown operation. Other agents continue to
use the same instance. A managed idalib worker cancels orphaned execution, saves,
and exits after its final lease disappears; GUI databases are never closed by
MCP lifecycle management. Low-level `DatabaseManager` users can set
`keepalive=30` (or another bounded duration) to retain an idle worker for reuse.

## Development checkout

```bash
uv sync
uv run ida-nexus mcp
```

## Releases

The manually dispatched `.github/workflows/release.yml` workflow bumps, commits,
tags, publishes to PyPI, and creates a GitHub release. For the initial release,
`release-current` publishes and tags the version already in the manifests without
bumping it. The Python package, IDA plugin, and HTTP server version declarations
are managed together by one script:

```bash
python scripts/bump_version.py --check
python scripts/bump_version.py dev
python scripts/bump_version.py release-patch
python scripts/bump_version.py release-minor
```

An exact version is also accepted. The `--check` command verifies that every
managed file has the same version. Each GitHub release also includes one
`ida-nexus-plugin-<version>.zip` asset for direct installation with HCLI.

The MCP server uses stdio by default. A local HTTP transport is also available:

```bash
uv run ida-nexus mcp --transport http://127.0.0.1:5001 --agent inspector
```

To manually play with the MCP, use the inspector:

```bash
npx -y @modelcontextprotocol/inspector
```

## Develop the Claude plugin locally

The plugin registers the MCP server as `ida`, so Claude Code tool names are shorter, e.g. `mcp__plugin_ida__open_database`. The first invocation of any matching `mcp__(.*[_:])?ida__.*` tool will trigger `uv` to install the server (cached after that) and fire the `PreToolUse` hook that injects the Claude session id for log correlation.

Clone the repo and launch Claude Code pointing at the checkout:

```bash
git clone https://github.com/HexRaysSA/ida-nexus
claude --plugin-dir ./ida-nexus
```

After editing `plugin.json`, hooks, or the Python source, run `/reload-plugins` inside Claude Code to pick up the changes without restarting. The manifest runs the MCP via `uv run --project ${CLAUDE_PLUGIN_ROOT} ...`, so local Python edits are reflected immediately - no rebuild step.

## Opening databases

Given an executable path, Nexus normally uses `<executable>.i64`. Given an
existing `.i64`, it uses that database directly.

```json
{
  "path": "/path/to/sample.exe",
  "set_current": true
}
```

Resolution proceeds as follows:

1. Use a registered GUI whose executable path matches.
2. Otherwise use the unique owner of the expected IDB.
3. Otherwise serialize creation and start a managed idalib worker.

All conceptual database access is read/write. Use `save_database` when an
explicit save is required.

## Executing Nexus Python

`execute_python` accepts ordinary Python with the current ida-domain `Database`
available globally as `db` and the imported package as `ida_domain`. A single
or trailing expression becomes the result:

```python
functions = list(db.functions)
{"count": len(functions), "first": functions[0].name}
```

Function-style code remains available and receives `db` by name:

```python
def run(db):
    return {
        "minimum_ea": db.minimum_ea,
        "maximum_ea": db.maximum_ea,
    }
```

Use `reference` before execution instead of guessing ida-domain API shapes. The
MCP execution first issues a separate, unbounded initial-autoanalysis wait for
each attached database. The upstream `/execute_python` route and client method
do not wait implicitly, so the script retains its full execution timeout. The
MCP tool defaults that execution-only timeout to 360 seconds and exposes it as
a numeric argument. MCP cancellation is handled concurrently: the tool sends a
lease- and operation-scoped `/cancel_operation` control request, waits for IDA
to unwind, and preserves the attached database handle.

Latency-sensitive clients should aggregate work into one snippet rather than
making one request per row or symbol. Each request requires one IDA main-thread
handoff, though the handoff itself is normally only a few microseconds in an
idle idalib worker. Return ordinary JSON-compatible dictionaries, lists, and
scalars: they are encoded directly off IDA's main thread. Unsupported Python or
IDA objects, bytes, and non-finite floats are rejected with `invalid_result`;
convert them explicitly in the executed code.

## Performance benchmark

Run the endpoint benchmark against an existing IDB to compare client-visible
latency across machines or revisions:

```bash
uv run ida-nexus benchmark /path/to/database.i64 \
  --output benchmark.json
```

The script holds a real `DatabaseHandle` lease and reports fresh TCP connection
cost, fresh and reused `/health`, fresh and reused trivial execution, the public
`DatabaseHandle.execute_python` path, an in-worker `ida_bytes.get_flags` loop,
and a roughly 35 KB JSON result. Timings include reading and decoding the HTTP
response. Defaults are 20 warmups and 200 measured requests; use
`--iterations`, `--warmup`, and `--workload-iterations` for quicker probes.
`--no-spawn` requires an already-running GUI or worker, `--json` prints only the
machine-readable schema-1 report, and `--output` preserves raw samples plus
summary percentiles for regression tracking.

Use the same IDB, backend, iteration counts, and otherwise-idle host when
comparing reports. `handle_open_ms` may include worker startup and is deliberately
kept separate from steady-state request metrics.

## Shared clients and lifecycle

Each open MCP handle maintains an authenticated SSE lease. Multiple agents and
MCP servers may open the same database and resolve to the same GUI or idalib
instance.

Closing a handle releases only that lease. After the final lease, managed
idalib workers cancel orphaned work, save and close the IDB on the idalib main
thread, and exit immediately unless that lease requested a bounded keepalive.
The fixed grace period applies only before the first lease. Crashed clients are
detected by SSE heartbeats. Hard-killed workers are detected by lifetime file
locks and reaped on the next scan.

There are no client process refcounts. The lease-scoped release route cannot
close another client's lease. A low-level client may request managed idalib
shutdown with `DatabaseHandle.shutdown_database(save=...)`, but only while its
lease is exclusive; GUI and shared instances reject the request.

## Local state

```text
<IDAUSR>/nexus/
  instances/<record-id>.json
  instances/<record-id>.lock
  spawn/<idb-key>.lock
  logs/<record-id>.log
  sessions/<session-id>.jsonl
```

`<IDAUSR>` is the first directory in the `IDAUSR` environment variable. When
unset, IDA's platform default is used (`~/.idapro` on Unix-like systems or
`%APPDATA%/Hex-Rays/IDA Pro` on Windows).

- `instances/` is the live discovery registry.
- `spawn/` serializes idalib worker creation.
- `logs/` contains IDA/worker operational output.
- `sessions/` contains semantic MCP and agent traces, including the configured
  agent name and MCP initialize client information/metadata.

Registry tokens and records are private to the local user. HTTP endpoints bind
to `127.0.0.1`, require bearer authentication, validate `Host`, reject browser
origins, and enforce bounded request decoding.

## Semantic session traces

Every MCP process writes one schema-1 JSONL trace:

```text
<IDAUSR>/nexus/sessions/<mcp-server-id>.jsonl
```

The trace contains:

- every MCP tool call, result, error, and duration;
- complete `reference` queries and results;
- executed Python and returned values;
- database open, reuse, disconnection, save, and release events;
- GUI or idalib record identity and worker log path;
- Claude, Codex, Pi, and `IDA_NEXUS_ID` session metadata.

Tool calls and results are paired by `call_id`; the dashboard shows the same
short call ID on both cards and exposes the full value in the badge tooltip and
`data-call-id` attribute. Shared worker operational logs are linked through
`record_id`.

Claude and Codex use the bundled `PreToolUse` hook to inject transcript paths as
hidden `_meta` values. The MCP server removes `_meta` from public arguments and
records it under the semantic session context. Pi session metadata is handled
the same way.

## Dashboard

Run the stdlib-only local dashboard with:

```bash
uv run ida-nexus dashboard --open
uv run ida-nexus dashboard --port 9000 \
  --sessions-dir "$IDAUSR/nexus/sessions"
```

The dashboard provides:

- a newest-first session index (startup/shutdown and internal lifecycle-only
  traces without MCP tool or linked-agent activity are hidden);
- running, closed, or killed status;
- all GUI and idalib targets used in one session;
- chronological tool-call and completion events with shared call-ID badges;
  database lifecycle events emitted inside a call carry the same badge;
- highlighted Python code and compact single-value `reference` queries;
- MCP `PythonExecutionResult` fields with string values rendered as unescaped
  text and empty stdout/stderr omitted; agent-side truncation notices show when
  the complete MCP result was not inserted into model context;
- model-facing MCP error payloads separated from clearly marked internal
  diagnostic metadata;
- logged reference output and structured errors;
- interleaved Claude, Codex, Pi, or oh-my-pi transcript activity with
  visibility checkboxes for the transcript and unsupported events;
- timestamped unsupported agent records as collapsed raw-JSON events rather
  than silently dropping them;
- token and estimated cost summaries, including separate cache-read and
  cache-write counts, where available;
- self-contained HTML export.

Only transcript paths referenced by semantic sessions may be served.

## Portable log archives

Create a support ZIP containing every local semantic session, each linked
Claude, Codex, or Pi transcript, and every file under
`<IDAUSR>/nexus/logs/`:

```bash
uv run ida-nexus logs
uv run ida-nexus logs --output support.zip
```

Pass one or more semantic session files to collect only those sessions:

```bash
uv run ida-nexus logs session-a.jsonl session-b.jsonl -o selected.zip
```

The ZIP contains `ida-nexus-logs.json`, a schema-versioned JSON table of
contents mapping semantic and agent session paths to archive members. Missing
linked transcripts are recorded in the TOC and reported as warnings.
Operational logs are preserved beneath `logs/` without TOC entries because the
dashboard does not resolve or render them. Open a bundle without accessing the
receiving machine's transcript paths with:

```bash
uv run ida-nexus dashboard --archive support.zip --open
```

`--sessions-zip` is an alias for `--archive`.

## Migrating pre-0.2 logs

The one-shot migration utility intentionally remains a project script rather
than an installed command:

```bash
uv run python scripts/migrate_logs.py --dry-run
uv run python scripts/migrate_logs.py --dry-run --verbose  # print every discarded record
uv run python scripts/migrate_logs.py
```

It reads legacy logs from `<IDAUSR>/nexus/logs`, reconstructs sessions using
per-request agent transcript paths or GUIDs, and writes the 0.2 schema under
`<IDAUSR>/nexus/sessions`.

Migration never modifies source logs. Known `bridge_output` records are
operational noise, so the default output reports a count per source file while
leaving the originals intact. `--verbose` prints every discarded record.
Unknown, malformed, and unattributable records are always printed with their
source file and line number rather than entering the permanent dashboard
schema.

## Running a worker directly

The resolver normally starts idalib workers on demand, but the worker is also
exposed as a console script for reuse and diagnostics. To verify that idalib
initializes without opening a database:

```bash
uv run ida-nexus worker --probe
```

To open one executable or IDB in idalib and serve the same authenticated
loopback HTTP API:

```bash
uv run ida-nexus worker /path/to/target.elf
```

It registers in the private registry just like a resolver-spawned worker, so
`open_database()` and the live endpoint check below discover it automatically.
Omit `--managed` (as above) to keep the worker running until interrupted; the
resolver passes `--managed` so workers exit after their final lease is released.

## Live endpoint check

For diagnostics, the live HTTP smoke test accepts an endpoint and discovers its
token from the private registry:

```bash
uv run python tests/test_live.py http://127.0.0.1:PORT --save
```

See [../docs/ARCHITECTURE.md](ARCHITECTURE.md) for lifecycle invariants, state
transitions, failure handling, and trace design.
