# Nexus GUI ownership and migration plan

Original proposal, 2026-09-06 against local HEAD `5eca557`. The current
implementation and its remaining limits are documented in [GUI-INTEGRATION.md](GUI-INTEGRATION.md).
The design below remains the rationale, rather than a claim that every proposed
capability is implemented.
The implementation belongs in `ida_nexus`. MCP, the web UI, and other clients use
ordinary database handles throughout an ownership change.

## Existing contracts and issues

- [#29: seamless GUI ↔ headless migration](https://github.com/HexRaysSA/ida-nexus/issues/29)
  is open. It asks for draining operations, blocking admission, launching the
  target, and recovering leases only after an explicitly identified migration.
- [#12: first GUI connection notification](https://github.com/HexRaysSA/ida-nexus/issues/12)
  is open. Launch/attachment needs a library/plugin policy for notification or
  consent; presentation is not an MCP concern.
- [#38: weak leases](https://github.com/HexRaysSA/ida-nexus/issues/38) and
  [#37: save/discard semantics](https://github.com/HexRaysSA/ida-nexus/issues/37)
  remain open and affect close behavior. Do not silently decide either by making
  an event observer own the database or letting one caller discard shared work.
- [#42: disabled analysis](https://github.com/HexRaysSA/ida-nexus/issues/42) and
  [#50: shutdown waits for saves](https://github.com/HexRaysSA/ida-nexus/issues/50)
  are closed. Reproduce remaining GUI-specific behavior before reopening a wider
  claim; retain native disabled-analysis and save/reopen regression tests.

Local code already has shared GUI and idalib owners, canonical IDB keys and
lifetime registration locks (`_registry.py`), owner resolution (`_resolver.py`),
per-handle leases (`handle.py`), admission/draining state (`_server.py`), and a
shared IDAPython runtime (`_runtime.py`). The GUI plugin registers a database
after opening it and releases registration after detaching (`plugin.py`).

Missing pieces are a supported GUI launcher, a pre-close lifecycle hook, an
ownership handoff protocol, and handle/subscription rebinding. `DatabaseHandle`
currently treats owner disconnect as terminal and deliberately does not replay
ambiguous failed POSTs. Preserve that protection.

## Public library surface

Illustrative usage:

```python
# Existing callers, including MCP, keep this behavior: reuse any live owner.
db = DatabaseHandle.open(path)

# Host-selected startup policy: create a GUI owner if no owner exists.
db = DatabaseHandle.open(path, options=DatabaseOpenOptions(backend="gui"))

# Explicit ownership transition; all handles for this database survive it.
transition = db.ensure_backend("gui", timeout=120)
transition = db.ensure_backend("idalib", timeout=120)
```

- Default `backend="auto"`: reuse either owner, otherwise launch idalib.
- `backend="gui"` / `"idalib"`: require that backend. Attach if already correct;
  use the same migration machinery when an owner of the other kind exists.
- Separate spawn/import options from migration options. Import options must never
  be reapplied to a saved IDB during handoff. Analysis state is a separate axis
  from backend and readiness; disabled analysis must remain disabled.
- Return a typed result containing logical database ID, transition ID, source and
  target backend, new generation, and any reset notices. Expose lifecycle events
  and a deadline/cancellation mechanism; do not encode these as HTTP strings that
  every consumer must parse.
- Provide a public GUI launch configuration/provider seam, owned by Nexus:
  executable discovery, argv construction, environment, bootstrap token, startup
  deadline, and process supervision. The default launches a local installed IDA.
  The hub supplies DISPLAY/desktop environment through that seam and retains
  responsibility for X/VNC/container presentation. Nexus must not depend on VNC.
- GUI focus/raise is an optional backend capability; it is not a reason to move
  backend decisions into MCP. A host chooses policy before creating its manager.
- Distinguish releasing a lease from closing a GUI window and from shutting down
  the database. Use a supported close request with an explicit result, replacing
  the hub's private control-file protocol.

## Ownership state machine

```text
closed → starting(gui|idalib) → ready(generation N)
ready → draining → saving → releasing native IDB → starting target
      → ready(generation N+1)
```

The logical database and lease identities remain stable; PID, port, token,
registry record and generation belong to an owner incarnation. Exactly one
process may have the native database open at any time.

Use a per-database handoff lock in addition to the native/lifetime owner lock.
All resolve/spawn paths check it. Keep a bounded transition record containing
the source generation, intended target, deadline and phase. Publish updates
atomically. A failed health probe alone must never authorize a new owner.

The transition needs a coordinator that survives the outgoing GUI/worker and
the initiating client. Implement it in the library as a short-lived supervised
helper for the handoff, using the registry and authenticated local IPC. Do not
make the MCP server or hub the only keeper of transition state. On coordinator
death, recovery must reconcile live locks and process identity before proceeding.

## Handoff protocol

1. Preflight the target executable, GUI environment, plugin/bootstrap availability
   and writable database destination before changing the source. Acquire the
   handoff lock; concurrent requests join the same transition or get a typed
   conflicting-target response.
2. Close request admission atomically, then drain accepted operations. Waiting
   clients receive an explicit migration response with generation/transition ID.
   Never close IDA while an accepted mutation is still executing. A long-running
   operation reaches the deadline visibly; do not kill it to meet the deadline.
3. Preserve lease identity/attribution, remaining lifetime policy and operation
   outcome metadata. Freeze analysis safely and persist its desired policy.
   A migration always preserves shared edits; it is not a save/discard vote.
4. Save once, await native completion, detach/close the database, and await native
   file-lock release. On save failure, reopen admission on the original owner
   and leave its database/window intact. Do not unpack a competing copy.
5. Launch the target on the saved IDB using a one-time bootstrap grant scoped to
   the database, transition and generation. Verify registration, canonical path,
   generation, backend and readiness. Discovery of an arbitrary new record with
   the same path is insufficient proof that it is the authorized successor.
6. Publish the new generation, transfer leases and notify waiting handles. Send
   an explicit database-resync notification to every event subscription, because
   event sequence numbers and in-memory caches belonged to the previous owner.
7. Retire the old control endpoint/helper after acknowledgments or the bounded
   transition grace period. Release the handoff lock only after publication or
   a reconciled failure state.

If target startup fails after a successful source close, attempt a controlled
rollback to the source backend using the saved IDB. If rollback fails, preserve
the IDB and report a typed recoverable startup failure to every lease; do not
claim success or silently open a blank/new database. Crash recovery remains a
different lifecycle from planned migration.

## Transparent handle recovery without duplicate edits

`DatabaseHandle` owns re-resolution, lease rebinding and subscription resumption.
`DatabaseManager` and MCP must not contain backend-specific retry branches.

- A request explicitly rejected before admission with `migrating` can wait and
  retry at the successor within its original deadline.
- An accepted operation must retain its operation ID and outcome classification.
  Do not blindly replay an `execute_python` POST after a socket failure. If the
  source completed it but its response was lost, return the recorded outcome or
  an explicit outcome-unknown error. General Python side effects are not replayable.
- Rebind concurrent handles once per generation, preserving logical lease IDs,
  attribution, callbacks and close-during-migration intent. Prevent a late attach
  from resurrecting a lease that was released during the transition.
- A migration notification is recoverable; an unrelated owner death remains an
  ordinary disconnect/crash. Authenticate the successor through local registry
  ownership and the transition grant, not a user-supplied network redirect.

## GUI startup and close behavior

GUI-first must work for both a raw binary and an existing IDB. Wait for the
plugin's registration rather than sleeping for a fixed duration. Return typed
loader/license/plugin/startup failures, leave useful logs, and clean up only the
processes launched by this attempt. Cover paths with spaces/Unicode and native
Windows, Linux DISPLAY, and macOS launch behavior.

For GUI → idalib when the user closes the window, intercept the close request
early enough to defer it while draining/saving; `plugin.term()` is too late to
implement a transactional handoff. Determine the supported IDA UI close/veto
hook in a native spike. The dialog's cancel path must leave the GUI unchanged.

If ordinary leases remain, start a managed headless successor with zero *extra*
keepalive after the transferred leases end (the intent of #29's “0 timeout”).
Zero must not mean “kill the successor before leases reattach.” If no ordinary
leases remain, close normally; weak observers should not force migration.
An application-wide quit closes presentation but must not kill a required
successor. Explicit “close database for everyone” is a distinct operation.

## Process-local state and GUI dispatch

The IDB can move; arbitrary Python globals, SWIG objects, undo stacks, plugin
state, debugger state and an in-flight decompiler object cannot be serialized
reliably. Emit a runtime-reset notice and invalidate remote modules, REPL
namespaces and decompiler caches. Persist IDB edits and supported cursor/view
state; do not promise Python variable or undo continuity across processes.
Reject or explicitly gate migration with an active debugger/modal operation.

Move GUI dispatch behavior into the runtime's supported GUI backend. The hub
currently replaces `_run_sync` with an idle/modal-aware queue to avoid observed
`MFF_WRITE` stalls when analysis is disabled. Reproduce that case against current
Nexus and implement safe dispatch, timeout and cancellation behavior there;
do not merely copy the monkeypatch as a public API. Avoid reentrant DB writes
while IDA is handling a modal dialog or another operation.

## Incremental implementation and acceptance

1. **Lifecycle and dispatcher:** establish admission/close contracts and typed
   lifecycle/reset events; native disabled-analysis/modal/cancel/save tests.
2. **GUI-first:** public launch provider plus default launcher, startup handshake,
   exact ownership checks and attach-to-existing-owner tests. No migration needed
   for this first useful release.
3. **Headless → GUI:** coordinator, handoff lock, drain/save/launch/publish,
   authenticated rebinding and operation outcome handling.
4. **GUI → headless:** verified pre-close hook, cancellation, remaining lease
   transfer, last-lease shutdown and reset semantics.
5. **Hub adoption:** remove private dispatcher and close control files; route
   desktop actions through the library. Keep MCP tool implementations unchanged.

Required multi-process/native scenarios: two clients opening through different
path aliases; two simultaneous migration requests; migration during rename and
long Python; close/cancel during migration; disabled analysis; missing GUI plugin;
license/loader/save errors; target/coordinator/source crash at every phase; lost
mutation responses; no live-owner stealing; reconnect and full event resync;
lease release/expiry races; save/reopen verifies known names, comments, types,
function and segment counts. Include one MCP + web + REPL participant scenario
whose MCP test uses only the existing tool surface.

Before implementation, agree on the backend-policy API, supported pre-close
hook, operation-outcome retention bounds, weak-lease semantics and reset UX.
No GUI migration implementation is included in this planning change.
