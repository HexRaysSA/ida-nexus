"""Reusable IDA GUI plugin lifecycle for the shared Nexus service.

This module is intended to be imported by IDAPython plugin entry points.  Each
entry point keeps its own ``plugin_t`` metadata and delegates explicitly to
``init()``, ``run()``, and ``term()``.  Module state makes those lifecycle calls
idempotent when several installed plugins provide Nexus integration.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import ida_kernwin
import ida_loader
import ida_nalt
import idaapi

from ._registry import REGISTRY_DIR, InstanceIdentity, find_gui_owner
from ._runtime import (
    AnalysisState,
    IDARuntime,
    IdbChangeState,
    create_autoanalysis_hook,
    reconcile_autoanalysis_state,
)
from ._server import NexusHTTPServer


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
        self.analysis_state: AnalysisState | None = None
        self.idb_change_state: IdbChangeState | None = None
        self._analysis_hook: Any = None
        self._ui_hook: _ReadyToRunHook | None = None
        self._runtime: IDARuntime | None = None
        self._server: NexusHTTPServer | None = None
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

        self.analysis_state = AnalysisState()
        self._analysis_hook = create_autoanalysis_hook(self.analysis_state)
        self._analysis_hook.hook()
        # The change hook is installed only while /idb_events has subscribers
        # and only after initial autoanalysis has finished.
        self.idb_change_state = IdbChangeState()
        # IDA's SWIG stubs model hook constructors with spurious arguments.
        hook_type: Any = _ReadyToRunHook
        ui_hook = hook_type(self)
        ui_hook.hook()
        self._ui_hook = ui_hook
        return True

    @staticmethod
    def _current_paths() -> tuple[str, str]:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
        exe_path = ida_nalt.get_input_file_path() or ""
        return (
            str(Path(idb_path).resolve()) if idb_path else "",
            str(Path(exe_path).resolve()) if exe_path else "",
        )

    def reconcile_autoanalysis(self) -> None:
        analysis_state = self.analysis_state
        if analysis_state is not None and not analysis_state.complete.is_set():
            reconcile_autoanalysis_state(
                analysis_state,
                disabled_is_complete=True,
            )

    def start_server(self) -> None:
        if self._server is not None or self._external_registration:
            return
        self.reconcile_autoanalysis()

        idb_path, exe_path = self._current_paths()

        # Back off if an older or otherwise independent provider already
        # registered this GUI database. New providers importing this module are
        # coordinated by the module-level component before reaching this check.
        if idb_path and find_gui_owner(idb_path) is not None:
            self._external_registration = True
            self.log("Database already registered, skipping...")
            return

        analysis_state = self.analysis_state
        idb_change_state = self.idb_change_state
        if analysis_state is None or idb_change_state is None:
            raise RuntimeError("IDA Nexus plugin component is not initialized")

        from ida_domain import Database

        database = Database.open()
        identity = InstanceIdentity(idb_path=idb_path, exe_path=exe_path, backend="gui")
        runtime = IDARuntime(
            backend="gui",
            database=database,
            analysis_state=analysis_state,
            idb_change_state=idb_change_state,
            unattributed_operation_label="IDA GUI",
        )
        server = NexusHTTPServer(
            runtime,
            identity,
            analysis_state,
            REGISTRY_DIR,
        )
        try:
            server.start()
        except Exception:
            try:
                database.unhook()
            finally:
                # start() may have acquired the lifetime lock before HTTP
                # startup or publication failed. Release it only after the
                # ida-domain database has detached from the GUI IDB.
                server.release_registration()
            raise
        self._runtime = runtime
        self._server = server
        self.log("Database registered successfully!")

    def run(self, *, caller: str) -> None:
        attribution = f" (initialized by {self.owner})" if caller != self.owner else ""
        if self._server is not None:
            message = (
                f"Shared IDA Nexus server running at {self._server.url}{attribution}"
            )
        elif self._external_registration:
            message = f"IDA Nexus database registered by another provider{attribution}"
        else:
            message = f"IDA Nexus server not running{attribution}"
        ida_kernwin.msg(f"[{caller}] {message}\n")

    def term(self) -> None:
        if self._ui_hook is not None:
            self._ui_hook.unhook()
            self._ui_hook = None
        server = self._server
        if server is not None:
            server.stop()
            self._server = None
        if self._runtime is not None:
            try:
                # Ensure the lazily-installed hook is gone before teardown.
                self._runtime.disable_idb_change_hook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG cleanup
                self.log(f"failed to remove idb-change hook: {exc}")
            if self._runtime.database is not None:
                try:
                    self._runtime.database.unhook()
                except Exception as exc:  # noqa: BLE001 -- best-effort SWIG cleanup
                    self.log(f"failed to detach database: {exc}")
            self._runtime = None
        if server is not None:
            # Release the lifetime lock only after detaching from the GUI IDB.
            server.release_registration()
        if self._analysis_hook is not None:
            self._analysis_hook.unhook()
            self._analysis_hook = None
        self.analysis_state = None
        self.idb_change_state = None
        self._external_registration = False


_component: _NexusPluginComponent | None = None


def init(*, owner: str) -> bool:
    """Initialize the shared GUI integration once.

    The first successful caller supplies both the owner name and lifecycle log
    prefix. Later callers are no-ops and return ``True``.
    """

    global _component
    if _component is not None:
        return True
    if not owner.strip():
        raise ValueError("owner must not be empty")

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
