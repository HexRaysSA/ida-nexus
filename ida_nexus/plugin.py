"""Reusable IDA GUI plugin lifecycle for the shared Nexus service.

This module is intended to be imported by IDAPython plugin entry points.  Each
entry point keeps its own ``plugin_t`` metadata and delegates explicitly to
``init()``, ``run()``, and ``term()``.  Module state makes those lifecycle calls
idempotent when several installed plugins provide Nexus integration.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import ida_kernwin
import idaapi

from ._registry import find_gui_owner
from ._session import NexusSession, current_database_paths


class _ReadyToRunHook(ida_kernwin.UI_Hooks):
    def __init__(self, component: _NexusPluginComponent) -> None:
        super().__init__()
        self.component = component

    def ready_to_run(self) -> None:
        try:
            self.component.start_server()
        except Exception as exc:  # noqa: BLE001 -- IDA startup may raise SWIG errors
            self.component.log(f"failed to start: {exc}")

    def postprocess_action(self) -> None:
        # IDA has restored the runtime analyzer from the persistent IDB setting
        # by this point. Reconcile explicit disable actions and queue-draining
        # scripts that did not emit auto_empty_finally.
        self.component.reconcile_autoanalysis()


class _NexusPluginComponent:
    def __init__(self, *, owner: str) -> None:
        self.owner = owner
        self.session: NexusSession | None = None
        self._ui_hook: _ReadyToRunHook | None = None
        self._external_registration = False

    def log(self, message: str) -> None:
        ida_kernwin.msg(f"[{self.owner}] {message}\n")

    def init(self) -> bool:
        # IDA's idalib UI compatibility shim reports is_idaq(), hence both checks.
        if not is_interactive_gui():
            return False
        if sys.version_info < (3, 11):  # noqa: UP036 -- plugin bypasses package metadata
            running = ".".join(str(part) for part in sys.version_info[:3])
            self.log(f"Python 3.11 or newer is required (running {running})")
            return False
        version = tuple(
            int(part) for part in idaapi.get_kernel_version().split(".")[:2]
        )
        if version < (9, 4):
            self.log("IDA 9.4 or newer is required")
            return False

        session = NexusSession(
            backend="gui",
            host="gui",
            managed=False,
            unattributed_operation_label="IDA GUI",
            log=self.log,
        )
        # The GUI kernel is final once plugins load, so track analysis from here.
        session.hook_analysis()
        self.session = session
        # IDA's SWIG stubs model hook constructors with spurious arguments.
        hook_type: Any = _ReadyToRunHook
        ui_hook = hook_type(self)
        ui_hook.hook()
        self._ui_hook = ui_hook
        return True

    def reconcile_autoanalysis(self) -> None:
        if self.session is not None:
            self.session.reconcile_autoanalysis(disabled_is_complete=True)

    def start_server(self) -> None:
        session = self.session
        if session is None:
            raise RuntimeError("IDA Nexus plugin component is not initialized")
        if session.server is not None or self._external_registration:
            return
        self.reconcile_autoanalysis()

        idb_path, _exe_path = current_database_paths()

        # Back off if an older or otherwise independent provider already
        # registered this GUI database. New providers importing this module are
        # coordinated by the module-level component before reaching this check.
        if idb_path and find_gui_owner(idb_path) is not None:
            self._external_registration = True
            self.log("Database already registered, skipping...")
            return

        # The GUI runs analysis in its own event loop; nothing to drive here.
        session.start(autoanalysis=False)
        self.log("Database registered successfully!")

    def run(self, *, caller: str) -> None:
        attribution = f" (initialized by {self.owner})" if caller != self.owner else ""
        server = self.session.server if self.session is not None else None
        if server is not None:
            message = f"Shared IDA Nexus server running at {server.url}{attribution}"
        elif self._external_registration:
            message = f"IDA Nexus database registered by another provider{attribution}"
        else:
            message = f"IDA Nexus server not running{attribution}"
        ida_kernwin.msg(f"[{caller}] {message}\n")

    def term(self) -> None:
        global _pending_release
        if self._ui_hook is not None:
            self._ui_hook.unhook()
            self._ui_hook = None
        session = self.session
        if session is not None:
            session.stop()
            # qexit() unloads plugins before closing the native database. Defer
            # release until normal UI dispatch resumes; on process exit the OS
            # releases the retained lifetime lock instead.
            _pending_release = session

            def release_when_idle() -> bool:
                global _pending_release
                if _pending_release is session:
                    _pending_release = None
                session.release()
                return False

            ida_kernwin.execute_ui_requests((release_when_idle,))
            self.session = None
        self._external_registration = False


_component: _NexusPluginComponent | None = None
_pending_release: NexusSession | None = None


def init(*, owner: str) -> bool:
    """Initialize the shared GUI integration once.

    The first successful caller supplies both the owner name and lifecycle log
    prefix. Later callers are no-ops and return ``True``.
    """

    global _component, _pending_release
    if _component is not None:
        return True
    if not owner.strip():
        raise ValueError("owner must not be empty")
    # A synchronous unload/reload can precede the queued release callback.
    pending, _pending_release = _pending_release, None
    if pending is not None:
        pending.release()

    component = _NexusPluginComponent(owner=owner)
    try:
        initialized = component.init()
    except Exception:
        component.term()
        raise
    if not initialized:
        return False
    _component = component
    return True


def start() -> None:
    """Start an initialized GUI service after its database becomes available."""

    component = _component
    if component is None:
        raise RuntimeError("IDA Nexus plugin is not initialized")
    component.start_server()


def run(*, caller: str) -> None:
    """Report shared service status for the plugin menu item being invoked."""

    component = _component
    if component is None:
        ida_kernwin.msg(f"[{caller}] IDA Nexus server not running\n")
        return
    component.run(caller=caller)


def term() -> None:
    """Tear down the shared GUI integration once."""

    global _component
    component, _component = _component, None
    if component is not None:
        component.term()


def is_interactive_gui() -> bool:
    """True only for the Qt GUI, never idat or idalib."""

    return bool(ida_kernwin.is_idaq() and os.environ.get("IDA_IS_INTERACTIVE") == "1")
