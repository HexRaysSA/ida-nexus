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

## Coverage and the code flashlight

The report generators and recorder live in the separate
[coverage-flashlight project](../../coverage-flashlight/README.md). This repository
only configures which source to measure. Until that package is published, the dev
dependency uses the editable sibling checkout at `../coverage-flashlight`.
`uv sync` installs it along with the other development dependencies.

```sh
# Static line/branch coverage, with a separate context for every selected case:
uv run flashlight pytest -- -q

# Ordered execution for every case (a separate recording pass):
uv run flashlight pytest --trace --max-events 500000 -- -q

# A smaller database lifecycle recording:
uv run flashlight pytest --trace -- tests/test_manager_scenarios.py tests/test_idalib_e2e.py -q

# Render existing combined coverage without executing tests:
uv run flashlight report
```

Open `htmlcov/flashlight.html` and `htmlcov/execution.html`. Both are standalone
HTML files with source snapshots. The static report shows measured line/branch
coverage per test; playback reveals executed lines in event order, including
Python worker processes and threads. Unrevealed ranges collapse into grey `…`
rows until **Reveal source context** is checked.

Source configuration in `pyproject.toml` measures `ida_nexus` for coverage and
adds `tests` for execution playback. Each selected pytest case runs in its own
process so its identity propagates to workers. All real IDA cases run by default.
This is slower than the ordinary suite and does not replace it for race/timing
checks. Unlike the original repository script, the default coverage command now
provides individual contexts for every test, not a combined `protocol` group.
The historical measurements below retain their original grouping.

Coverage runs replace `.coverage`; use `--data-file path` to collect separately.
Trace runs preserve coverage data. To regenerate standard reports:

```sh
uv run coverage html
uv run coverage json
```

Use `flashlight run -- script.py ...` or `flashlight run -m package ...` for
single script/module coverage, and add `--trace` for ordered playback. A command
runs its target once; generating both reports requires two explicit passes.
See the separate project's README for source selection, CLI options, capture
limits, and report controls.

Native IDA/C++, pre-existing GUI processes and dynamically generated request
code are outside Python capture. Hard process termination can lose a buffered
tail; the abrupt-client-exit scenario deliberately exercises this and is flagged.
Coverage and tracing change timing; keep running the ordinary full suite.

### Initial measurement: 2026-09-05

Measured locally on Windows with Python 3.11.1 and coverage.py 7.16.0, against
the package at `bd68307`. The protocol suite and all 11 real-IDB cases passed
under instrumentation. These are observed results, not coverage requirements;
thread scheduling can change which incidental cleanup branches execute.

| Scope | Executed lines | Executed branch alternatives |
| --- | --- | --- |
| Entire `ida_nexus` package, combined runs | 5,445 / 7,807 (69.7%) | 1,640 / 2,756 (59.5%) |
| Database lifecycle modules, combined runs | 2,573 / 3,114 (82.6%) | 777 / 1,122 (69.3%) |
| Database lifecycle modules, real-IDB runs only | 2,350 / 3,114 (75.5%) | 629 / 1,122 (56.1%) |

The lifecycle subset is `manager.py`, `handle.py`, `instances.py`,
`database_state.py`, `_resolver.py`, `_registry.py`, `_server.py`, `_runtime.py`,
and `cli/worker.py`. The package total includes the dashboard, reference search,
GUI plugin, and other CLI commands. Existing coverage exclusions are respected;
no extra exclusions or percentage gates were introduced for this measurement.

The coverage-driven scenarios below now exercise same-path manager reuse,
bounded retry after a lease-handshake failure, scheduled startup failure,
and resolver startup-failure diagnostics. Line color alone does not establish
correctness: tests must assert the externally important consequence.

### After the scenario review: 2026-09-05

Measured on the same Windows environment, after the lifecycle fixes and
deletions. All 324 protocol/unit cases and 15 real-IDB cases passed under
instrumentation; the POSIX flock test is skipped on Windows. This adds 109
test cases, including four real-IDB cases, relative to the initial measurement.
The complete uninstrumented suite also passed: 339 passed, 1 skipped, and
3 subtests passed in 99.79 seconds. Ruff checks and formatting passed for all
changed Python files.

| Module / scope | Line coverage before → after | Branch coverage before → after |
| --- | --- | --- |
| Manager | 79.2% → 98.7% | 63.9% → 94.5% |
| Resolver | 79.5% → 92.7% | 75.3% → 87.3% |
| Registry | 79.9% → 87.1% | 63.7% → 78.4% |
| Handle and event subscription | 82.0% → 86.1% | 66.2% → 70.3% |
| Server | 88.7% → 89.8% | 77.3% → 80.6% |
| IDA runtime | 89.0% → 93.2% | 71.9% → 78.1% |
| Disk-state inspection | 63.5% → 67.0% | 46.3% → 53.7% |
| All nine lifecycle modules | 82.6% → 88.5% | 69.3% → 78.1% |
| Lifecycle modules, real-IDB runs only | 75.5% → 76.9% | 56.1% → 58.1% |

Combined lifecycle coverage is 2,736 / 3,090 executable lines and 872 / 1,116
branch alternatives. Real-IDB-only coverage is 2,377 / 3,090 lines and
648 / 1,116 branches. Deleting unused code reduced the executable-line
denominator by 24; the increase is not solely additional execution.

Residual gaps are visible in the flashlight. They include SSE malformed-event
and socket-cleanup paths, startup/teardown failures, input-validation alternatives,
and OS-specific file inspection. Disk-state coverage includes Linux/macOS code
that this Windows run cannot exercise. The manager's four unexecuted statements
are its successful-startup diagnostic, connected cancellation forwarding,
unavailable-owner listing status, and invalid-shutdown-timeout rejection.
These have valid purposes; they have not been deleted or excluded to raise a
percentage. The matrix below records the lifecycle contracts, not a claim
that every retained branch has now been asserted or every interleaving exhausted.

## Lifecycle contracts and why the code exists

The tests are the executable specification. These are the failure boundaries
that justify the management machinery; test names describe the narrower cases
and parametrized alternatives. Paths below are relative to `tests/`.

| Retained mechanism | Consequence it prevents / scenario that requires it | Tests |
| --- | --- | --- |
| OS lifetime lock separate from registry JSON and HTTP health | Damaged metadata, a failed health check, or a draining owner must not permit a second owner; dead records can be reaped. | `test_registry_scenarios.py`; `test_instance_management.py::test_draining_owner_remains_discoverable_until_database_close` |
| Resolver spawn lock and second ownership scan | Concurrent creators must share one worker; `new_database` must reject an owner discovered before or after acquiring the lock. | `test_resolver_scenarios.py::test_fresh_database_refuses_owner_on_either_side_of_spawn_lock`; E2E `test_process_clients_share_one_worker_and_persist_changes` |
| GUI executable identity plus explicit IDB identity | Default opens may reuse an unsaved GUI; custom-output opens must not attach to a different IDB from the same input. Ambiguous/blocked owners must fail closed. | `test_resolver_scenarios.py`; existing GUI identity tests in `test_instance_management.py` |
| Disk lock/header inspection before opening | An unregistered IDA owner must remain untouched; orphan components and malformed headers must not be interpreted as recoverable databases. | `test_database_state.py`; E2E `test_unregistered_idalib_owner_is_busy_until_it_closes` |
| Crash backup and post-copy ownership check | Backup/copy/fsync failure or an owner arriving during recovery must preserve originals and prevent launch. A packed base restores saved data; no packed base requires repair and an initial save. | `test_database_state.py`; `test_resolver_scenarios.py::test_failed_or_racing_crash_backup_never_starts_worker`; both E2E `test_worker_crash_invalidates_handle_and_recovers_database` cases |
| Startup deadline, launcher suffix, log-tail diagnostics | A Windows launcher can exit before its Python child; unrelated/wrong-IDB records cannot satisfy readiness. Failure must release the spawn lock and remain diagnosable on retry. | `test_resolver_scenarios.py`; `test_instance_management.py::test_await_ready_accepts_console_launcher_child_pid` |
| One bounded retry during open, exact identity afterward | A zero-lease owner can stop before the handshake; an established or explicitly attached handle must never silently switch databases. | `test_handle_scenarios.py`; crash E2Es |
| Persistent SSE lease separate from cached RPC socket | RPC idle recycling or a lost reply must not lose ownership. A completed mutation must never replay; the next explicit request can reconnect. | `test_handle_scenarios.py::test_lost_response_never_replays_mutation_and_next_request_reconnects`; `test_idle_rpc_connection_is_recycled_without_replacing_lease` |
| Per-lease state, cancellation, idle/keepalive policy | Releasing, expiring, or cancelling one client must preserve peers and must not cancel a successor operation. Queued requests cannot execute after release/cancellation; duplicate IDs and busy shutdown cannot interrupt active work. Last release saves and ends ownership. | `test_lease_scenarios.py`; lease/cancellation tests in `test_instance_management.py` and `test_nexus_server.py`; sharing, idle, keepalive, namespaces and cancellation E2Es |
| Manager open lock, attachment deduplication, explicit selection | Duplicate opens and executable/IDB aliases retain one local lease; closing a selected database chooses a survivor; failed IDs stay invalid. | `test_manager_scenarios.py`; E2E `test_manager_selection_aliases_and_shutdown_save_every_database` |
| Disconnect callback and actual-IDB failure lookup | The monitor can mark a handle disconnected before invoking the manager callback; custom GUI IDBs must be probed at their actual location. Both timing windows must classify crashes correctly. | `test_manager_scenarios.py::test_disconnected_handle_is_rejected_before_monitor_callback`; custom GUI crash scenario; E2E `test_manager_crash_requires_explicit_reopen_and_keeps_other_database` |
| Analysis completion cache and explicit save acknowledgement | Incomplete analysis must not be cached as done. IDA save failure, GUI Save As requirements, and malformed acknowledgements must not emit successful-save events or detach a usable database. | Analysis/save scenarios in `test_manager_scenarios.py`, `test_runtime.py`, and `test_handle_scenarios.py` |
| Terminal, serialized shutdown with concurrent drains | Shutdown must include an in-flight open, release all databases within a shared budget, and reject new opens. Event callbacks may request shutdown reentrantly. | Shutdown tests in `test_instance_management.py`; reentrant callback test in `test_manager_scenarios.py`; E2E `test_shutdown_waits_for_in_flight_real_idalib_open` |

The review removed the handle's unused lease-replacement method and RPC
port-switch check: a handle is bound to one instance for its entire lifetime.
It also removed the disconnected-session record class and its unread reason
field; the manager only needs the actual IDB path. Regression tests exposed and
fixed wrong-path crash detection, the pre-callback crash-classification race,
and a successful-save event emitted before validating the returned path.

New fault tests replace only the relevant boundary: a handshake failure, a
reply lost after the server has completed a real POST, an IDA save return value,
a filesystem failure, or an ownership scan at a specified instant. They assert
preserved bytes, identities, usable peers, event contents, or absence of a
worker launch. They are not substitutes for the real-IDB scenarios below.

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
| User Python failure | Both ordinary exceptions and `SystemExit` return structured errors; the writer and peer remain usable; a prior rename survives save and reopen. |
| Custom output and fresh replacement | Saved contents reopen at the chosen IDB path despite supplied import options; fresh creation is rejected while owned, then replaces the saved database from the input after release. |
| Manager crash and recovery | A dead worker is classified as crashed, another database stays usable, explicit reopen recovers flushed changes, and the old manager ID cannot address the replacement. |
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
- Exhaustive import-option combinations, license failures,
  and CLI/MCP transport lifecycles. Much of this has unit or protocol coverage,
  but the real-worker suite is centered on the Python database-management API.

Keep deterministic race and malformed-input tests: E2E tests complement them
rather than relying on scheduling luck to exercise every branch.
