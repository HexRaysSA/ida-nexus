# Database lifecycle testing

Development environments are expected to have IDA installed and idalib
configured. Run the complete suite with:

```sh
uv run pytest
```

Real-worker tests run by default. Select them, or exclude them on a machine
without IDA, with:

```sh
uv run pytest -m idalib_e2e -v
uv run pytest -m "not idalib_e2e"
```

`uv run ida-nexus worker --probe` checks idalib initialization. E2E tests fail
when IDA cannot start; they do not silently skip an installation problem.
The old `IDA_NEXUS_RUN_IDALIB_E2E` opt-in is no longer needed.

## What each layer proves

`test_instance_management.py` and `test_nexus_server.py` mostly use real
loopback HTTP, SSE connections, threads, and registry locks with a fake IDA
backend. They test lease accounting, request ownership, protocol validation,
discovery, and controlled interleavings. Their simulated backend cannot prove
that IDA saves a valid database, honors cancellation, or repairs crash files.

`test_database_state.py` covers malformed headers, partial component sets,
recovery decisions, and backup behavior using constructed files. This is
useful for deterministic error cases, but does not replace real IDA file tests.

`test_idalib_e2e.py` exercises the public API against actual worker processes:

| Scenario | Observable assertions |
| --- | --- |
| Concurrent clients in separate Python processes | Both openers rendezvous before opening; one worker is discovered; both see a shared rename; releasing one client preserves its peers; exclusive shutdown is rejected while shared. |
| Final release and reopen | Lifetime ownership ends, the packed IDB exists, and a new worker reads the saved rename. |
| Abrupt client exit | Killing the last client without cleanup releases its SSE lease; IDA saves the mutation and exits. |
| Unregistered IDA owner | A separate raw idalib process holds the real IDB lock; Nexus refuses to spawn over it and opens successfully after it closes. |
| Deferred analysis and execution state | Attaching a peer does not start disabled worker analysis; explicit analysis completes; persistent globals are lease-scoped and stateless execution clears them. |
| IDB events | A subscription opened before analysis receives actual rename hooks afterward, with increasing revisions and correct operation/origin attribution. |
| Idle leases | An executing request survives its idle deadline; expiration later invalidates only that lease and leaves an indefinite peer usable. |
| Keepalive and discard | Reattachment reuses the worker; exclusive shutdown without saving restores the previously saved contents on reopen. |
| Worker death without a packed base | Flushed changes survive repair; a replacement worker creates a packed base; the failed handle remains unusable. |
| Worker death with a packed base | Reopening restores saved contents; the dirty unpacked files are backed up byte-for-byte; the failed request is not replayed. |
| Timeout and cancellation | Real Python loops terminate with the expected errors; the same worker executes subsequent requests successfully. |
| Manager lifecycle | Executable/IDB aliases share one attachment; current selection falls back after close; stale IDs fail; shutdown saves both databases and rejects later opens. |
| Shutdown racing with open | A real acquired handle is paused before manager installation; shutdown waits and releases the actual worker. |

The shutdown race test wraps the real open only to hold that precise boundary.
The other E2E tests do not mock Nexus, IDA, transport, or filesystem operations.
File barriers coordinate processes; bounded polling waits for observable state.
Worker death uses `os._exit()` to bypass cleanup without creating a native crash
dialog. Inputs are temporary copies of the small bundled ELF; the test registry
is isolated from personal Nexus sessions. These tests should run serially:
the existing suite clears its shared test registry between tests.

## Remaining limits

This is not exhaustive coverage. The suite still needs manual or separate
environment coverage for:

- The real GUI plugin: loading/unloading, unsaved databases, temporary versus
  persistent analysis suspension, and GUI shutdown. Fake GUI backends verify
  protocol rules, not IDA's UI lifecycle.
- Large or slow databases, long native/decompiler operations, disk-full or
  permission failures during packing, and a process killed midway through a save.
- Native corruption and unrecoverable IDBs. Abrupt process exit tests lifecycle
  recovery, not every possible form of database corruption.
- Platform/filesystem differences. Run the real-worker suite on each supported
  OS; a successful local run does not establish NFS/SMB locking guarantees.
- Exhaustive import-option combinations, custom output paths, license failures,
  and CLI/MCP transport lifecycles. Much of this has unit or protocol coverage,
  but the real-worker suite is centered on the Python database-management API.

Keep deterministic race and malformed-input tests: E2E tests complement them
rather than relying on scheduling luck to exercise every branch.
