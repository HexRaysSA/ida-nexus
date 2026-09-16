# Contributing

⚠️ **We do not accept pull requests at this time.** ⚠️

If you run into problems with the installation, feel free to open an issue!

## Development checkout

```bash
uv sync
uv run pytest
uv run ida-nexus --help
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

Use `reference` before execution instead of guessing ida-domain API shapes.
The `/execute_python` route and client method do not wait for autoanalysis
implicitly; adapters choose when to call `wait_autoanalysis()`. Cancellation is
lease- and operation-scoped, waits for IDA to unwind, and preserves the attached
database handle.

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

Each open `DatabaseHandle` maintains an authenticated SSE lease. Multiple
adapters may open the same database and resolve to the same GUI or idalib
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
- `sessions/` is reserved for adapter-owned semantic sessions; IDA MCP stores
  its traces there so existing Nexus state directories remain discoverable.

Registry tokens and records are private to the local user. HTTP endpoints bind
to `127.0.0.1`, require bearer authentication, validate `Host`, reject browser
origins, and enforce bounded request decoding.

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
