"""Serve the database that is open in this IDA process.

The three hosts share this module. The GUI plugin, the ``idat`` bootstrap and
the idalib worker each get IDA to open a database and each run their own main
loop; attaching to that database, serving it, registering it, and detaching
again is the same everywhere and lives here.
"""

from __future__ import annotations

import argparse
import math
import os
import signal
import sys
import traceback
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ._registry import REGISTRY_DIR, BackendName, HostName, InstanceIdentity
from ._runtime import (
    AnalysisState,
    IDARuntime,
    IdbChangeState,
    create_autoanalysis_hook,
    reconcile_autoanalysis_state,
)
from ._server import DEFAULT_LEASE_GRACE_SECONDS, NexusHTTPServer


def add_lifecycle_arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """The arguments a host passes to the session; IDA switches never appear here."""
    parser.add_argument(
        "--managed",
        action="store_true",
        help="Exit after the last Nexus client lease is released",
    )
    parser.add_argument("--record-suffix", help=argparse.SUPPRESS)
    parser.add_argument(
        "--lease-grace",
        type=float,
        default=DEFAULT_LEASE_GRACE_SECONDS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--auto-analysis",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Start IDA autoanalysis in the background after publishing",
    )
    parser.add_argument(
        "--save-after-open", action="store_true", help=argparse.SUPPRESS
    )
    return parser


def validate_record_suffix(suffix: str) -> str:
    if len(suffix) != 6 or any(c not in "0123456789abcdef" for c in suffix):
        raise ValueError("record suffix must be six lowercase hexadecimal characters")
    return suffix


def validate_lease_grace(lease_grace: float) -> float:
    if not math.isfinite(lease_grace) or lease_grace < 0:
        raise ValueError("lease grace must be a finite non-negative number")
    return lease_grace


def current_database_paths() -> tuple[str, str]:
    """Resolved IDB and input paths of the database IDA has open."""
    import ida_loader
    import ida_nalt

    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    exe_path = ida_nalt.get_input_file_path() or ""
    return (
        str(Path(idb_path).resolve()) if idb_path else "",
        str(Path(exe_path).resolve()) if exe_path else "",
    )


def save_current_database() -> str:
    """Pack the open database to its own path; returns that path."""
    import ida_loader

    path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    if not path or not ida_loader.save_database(path, 0):
        raise RuntimeError("IDA failed to save the database")
    return path


def _print_log(message: str) -> None:
    print(f"[ida-nexus] {message}", file=sys.stderr, flush=True)


class _IdaproUnavailable(types.ModuleType):
    """Stands in for ``idapro`` inside IDA, where the library cannot load."""

    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(
            f"idapro.{name} is unavailable inside IDA; this database is owned by "
            "the IDA process, not by idalib"
        )


def _prepare_ida_domain() -> None:
    """Let ida-domain import inside ``idat``.

    ida-domain decides whether to load idalib with ``is_ida_library()``, which
    idat answers with True even though IDAPython is already running. It then
    imports ``idapro``, which refuses to load inside IDA. IDAPython leaves
    ``IDAPYTHON_VERSION`` in ``__main__`` (the signal idapro itself relies on),
    so inside IDA a placeholder takes the import's place. Nothing in Nexus
    calls into idapro there: IDA owns the database lifecycle.
    """
    if "idapro" in sys.modules:
        return
    main = sys.modules.get("__main__")
    if main is None or getattr(main, "IDAPYTHON_VERSION", None) is None:
        return
    import ida_kernwin

    # The SWIG stub types the output parameters as ints; None is what works.
    kernwin: Any = ida_kernwin
    if kernwin.is_ida_library(None, 0, None):
        sys.modules["idapro"] = _IdaproUnavailable("idapro")


class NexusSession:
    """One served database: runtime, HTTP server and registry record.

    ``start()`` attaches to the database IDA currently has open, so the host
    opens it first. ``stop()`` detaches from it again and ``release()`` then
    withdraws the registry record; the host closes the database in between so
    nobody can reopen the IDB while it is still being written.
    """

    def __init__(
        self,
        *,
        backend: BackendName,
        host: HostName,
        managed: bool,
        record_suffix: str | None = None,
        lease_grace: float = DEFAULT_LEASE_GRACE_SECONDS,
        unattributed_operation_label: str | None = None,
        on_shutdown: Callable[[], None] | None = None,
        log: Callable[[str], None] = _print_log,
    ) -> None:
        self.backend: BackendName = backend
        self.host: HostName = host
        self.managed = managed
        self.record_suffix = record_suffix
        self.lease_grace = validate_lease_grace(lease_grace)
        self.unattributed_operation_label = unattributed_operation_label
        self.on_shutdown = on_shutdown
        self.log = log
        self.analysis_state = AnalysisState()
        # The change hook is installed only while /idb_events has subscribers
        # and only after initial autoanalysis has finished.
        self.idb_change_state = IdbChangeState()
        self._analysis_hook: Any = None
        self.database: Any = None
        self.runtime: IDARuntime | None = None
        self.server: NexusHTTPServer | None = None

    def hook_analysis(self) -> None:
        """Track autoanalysis; hosts call this once IDA's kernel is final.

        The GUI plugin hooks during plugin init. The headless hosts hook after
        the database is open, because idalib reinitializes its kernel when it
        is given command options and would drop hooks installed before that.
        """
        if self._analysis_hook is None:
            self._analysis_hook = create_autoanalysis_hook(self.analysis_state)
            self._analysis_hook.hook()

    def reconcile_autoanalysis(self, *, disabled_is_complete: bool = False) -> None:
        if not self.analysis_state.complete.is_set():
            reconcile_autoanalysis_state(
                self.analysis_state, disabled_is_complete=disabled_is_complete
            )

    def start(self, *, autoanalysis: bool) -> NexusHTTPServer:
        """Attach to the open database, publish it, and optionally analyze it."""
        if self.server is not None:
            return self.server
        _prepare_ida_domain()
        from ida_domain import Database

        self.hook_analysis()
        idb_path, exe_path = current_database_paths()
        database = Database.open()
        identity = InstanceIdentity(
            idb_path=idb_path,
            exe_path=exe_path,
            backend=self.backend,
            managed=self.managed,
            host=self.host,
        )
        runtime = IDARuntime(
            backend=self.backend,
            database=database,
            analysis_state=self.analysis_state,
            idb_change_state=self.idb_change_state,
            unattributed_operation_label=self.unattributed_operation_label,
        )
        server = NexusHTTPServer(
            runtime,
            identity,
            self.analysis_state,
            REGISTRY_DIR,
            record_suffix=self.record_suffix,
            lease_grace=self.lease_grace,
            on_shutdown=self.on_shutdown,
        )
        try:
            server.start()
        except Exception:
            try:
                database.unhook()
            finally:
                # start() may have acquired the lifetime lock before HTTP
                # startup or publication failed. Release it only after the
                # ida-domain database has detached from the IDB.
                server.release_registration()
            raise
        self.database = database
        self.runtime = runtime
        self.server = server
        if autoanalysis:
            server.start_autoanalysis()
        return server

    def stop(self) -> None:
        """Stop serving and detach from the database; the record stays until release()."""
        server = self.server
        if server is not None:
            server.stop()
        runtime = self.runtime
        if runtime is not None:
            try:
                # Ensure the lazily-installed hook is gone before teardown.
                runtime.disable_idb_change_hook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG hook cleanup
                self.log(f"failed to remove idb-change hook: {exc}")
            runtime.database = None
            self.runtime = None
        database = self.database
        if database is not None:
            try:
                database.unhook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG cleanup
                self.log(f"failed to detach database: {exc}")
            self.database = None

    def release(self) -> None:
        """Withdraw the registry record once the host has closed or kept the IDB."""
        server = self.server
        self.server = None
        if server is not None:
            server.release_registration()
        # IDAPython TESTABLE_BUILD requires user hooks to be gone before kernel
        # or database teardown. In release builds this also avoids relying on
        # IDAPython's forced stale-hook cleanup.
        if self._analysis_hook is not None:
            try:
                self._analysis_hook.unhook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG hook cleanup
                self.log(f"failed to remove analysis hook: {exc}")
            self._analysis_hook = None


def serve_headless(args: argparse.Namespace) -> int:
    """Serve the database ``idat`` opened until the last lease or a signal ends it.

    IDA closes the database when the process exits. The session saves first
    (or marks the unpacked files for deletion when the shutdown asked to
    discard) and only then releases its registration, so a client that reopens
    the IDB right away finds the packed base complete.
    """
    import ida_kernwin
    import ida_loader

    # serve()/stop_serving() exist in IDA 9.4+; older stubs do not declare them.
    kernwin: Any = ida_kernwin
    suffix = validate_record_suffix(args.record_suffix or os.urandom(3).hex())
    session = NexusSession(
        backend="idalib",
        host="idat",
        managed=args.managed,
        record_suffix=suffix,
        lease_grace=args.lease_grace,
        on_shutdown=kernwin.stop_serving,
    )
    server: NexusHTTPServer | None = None
    stop_signal: int | None = None

    def request_stop(signum: int, frame: Any) -> None:
        nonlocal stop_signal
        stop_signal = signum
        kernwin.stop_serving()

    previous_handlers: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)
    try:
        if args.save_after_open:
            save_current_database()
        server = session.start(autoanalysis=args.auto_analysis)
        print(f"[ida-nexus] {server.url}", flush=True)
        # A signal received during startup must not be lost before serve() begins.
        if stop_signal is None:
            kernwin.serve()
        return 128 + stop_signal if stop_signal is not None else 0
    except Exception as exc:  # noqa: BLE001 -- IDA is third-party code
        print(f"[ida-nexus] {exc}", flush=True)
        traceback.print_exc()
        return 1
    finally:
        session.stop()
        save = server.save_on_shutdown if server is not None else True
        try:
            if save:
                save_current_database()
            # Saved already, or asked to discard: IDA only removes the unpacked
            # files on exit and leaves the packed base alone.
            ida_loader.set_database_flag(ida_loader.DBFL_KILL)
        except Exception as exc:  # noqa: BLE001 -- leave IDA's own save as the fallback
            print(f"[ida-nexus] failed to save database: {exc}", flush=True)
        session.release()
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


def run_bootstrap(argv: list[str], *, interactive: bool) -> int | None:
    """Entry point for the ``-S`` bootstrap; returns an exit code for ``idat``.

    In the GUI the installed plugin already registers the database, so the
    bootstrap only hands the window back to the user. It returns None and IDA
    keeps running.
    """
    parser = add_lifecycle_arguments(
        argparse.ArgumentParser(prog="ida_nexus_bootstrap")
    )
    args = parser.parse_args(argv)
    if interactive:
        import ida_kernwin
        import idc

        # -A skipped the loader dialog and other prompts while loading; from here
        # on the user owns the window and should see dialogs again. IDA restores
        # the batch flag when a -S script returns, so switch it off afterwards.
        def interactive_again() -> int:
            idc.batch(0)
            return -1

        ida_kernwin.register_timer(0, interactive_again)
        if args.save_after_open:
            save_current_database()
        return None
    return serve_headless(args)
