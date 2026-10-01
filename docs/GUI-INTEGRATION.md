# GUI ownership and migration

Implemented in the working tree on 2026-09-06. This is a library feature;
MCP's normal open/execute/save operations do not contain migration logic.

```python
from ida_nexus import DatabaseHandle, DatabaseOpenOptions, GuiLaunchOptions

# Default: reuse whichever backend already owns the database.
db = DatabaseHandle.open(path)

# Explicitly request a GUI owner, including for a previously unopened binary.
gui = GuiLaunchOptions(executable="/opt/ida/ida", environment={"DISPLAY": ":1"})
db = DatabaseHandle.open(path, options=DatabaseOpenOptions(backend="gui", gui=gui))

# Existing handles and event subscriptions follow this explicit handoff.
db.ensure_backend("gui", gui=gui, timeout=120)
db.ensure_backend("idalib", timeout=120)
```

`GuiLaunchOptions` supplies an executable and presentation environment. Without
an executable, discovery uses `IDA_GUI_EXECUTABLE` and then PATH. Nexus has no
VNC, browser or web UI dependency. The GUI plugin must be installed normally.
Startup accepts configured loading defaults; the resulting application is
interactive. `auto_analysis=False` is supported. The bootstrap owns IDA's `-S`
switch, so custom startup scripts should currently run through the returned
handle instead of `script_file`. Import-only switches are dropped for existing
IDBs, matching headless behavior.

## Handoff contract

- A detached library coordinator holds the normal per-IDB spawn lock. Concurrent
  same-target migration requests join the transition; opposite requests fail.
- The source rejects new operations before admission and drains already accepted
  work. A safe GUI-thread dispatcher avoids IDA's stalled background write queue.
- The source pauses analysis and saves before closing. The coordinator waits for
  both registration release and full process exit before launching the target;
  GUI plugin termination can precede IDA's final file teardown. Debugger sessions,
  temporary databases and unwritable paths reject migration before release.
- Source client leases are reserved at the target for up to 30 seconds. An early
  reconnect/disconnect cannot shut it down before slower clients reattach.
- Private transition records authenticate the outgoing incarnation with its token.
  Handles rebind only for that planned transition and retain their lease/origin IDs.
  Event subscriptions reopen and emit a `runtime_reset` event.
- Transport failures never replay Python mutations. Only an explicit pre-admission
  `migrating` rejection can be retried against the new owner. A lost release
  acknowledgement is reconciled through ownership checks without repeating release.
- A failed save restores admission to the original process. A failed target launch
  attempts rollback only after native ownership is released. A still-live owner is
  never overwritten or force-killed to make rollback succeed. Source admission has
  a deadline watchdog if the coordinator disappears before release.

Closing IDA's main window or Quit action with connected clients requests migration
to idalib. With no clients, normal GUI close applies. The embedding host can use
`ensure_backend("idalib")` before releasing its display.

## State and limits

Database edits survive. Python globals, remote module installations, native GUI
widgets and undo/redo history are process-local and reset. `RemoteModule` already
reinstalls on an explicit missing-module result. Other clients should listen to
`runtime_reset` or `add_lifecycle_listener` and invalidate their own caches.
Cursor/selection state belongs to each client, not a shared GUI screen address.

Migration is bounded to 600 seconds. Native dialogs can prevent admission; dismiss
them and retry. A coordinator/process crash after source release can still leave
an unavailable owner or a failed transition requiring operator diagnosis; this
is not automatic crash recovery. Log files and saved IDBs are retained. The GUI
launcher has no installation picker and no interactive custom loader-dialog API.
Headless analysis policy is retained from worker startup; changing that policy by
arbitrary Python is not currently a separate tracked library setting.

## Validation

Pure tests cover draining, rejected operations, failed saves, authenticated
rebinding of two handles and an event subscription, reservation lifetime, normal
crash behavior, and at-most-once mutation requests. Native Linux/IDA 9.4 tests use
copied fixtures: headless → GUI → headless, GUI-first loading, native main-window
close with multiple clients, event stream continuity, MCP manager continuity,
read-only refusal, failed-target rollback and function-count retention.
The hub browser test additionally covers first-viewer resizing and handoff without
reconnecting VNC. Windows GUI behavior still needs a native platform test before
claiming cross-platform release readiness.

Run native tests explicitly in an installed IDA environment with its GUI plugin
and a display, for example:

```sh
IDA_NEXUS_TEST_GUI=/opt/ida/ida DISPLAY=:1 pytest tests/test_gui_e2e.py -q
```
