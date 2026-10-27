import argparse
import importlib
import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from .._launch import _disarm_startup_cleanup, join_ida_switches
from .._registry import LOG_DIR, ensure_private_directory
from .._session import (
    NexusSession,
    add_lifecycle_arguments,
    save_current_database,
    validate_lease_grace,
    validate_record_suffix,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-nexus worker",
        description=(
            "Open one executable or IDB with idalib and expose the IDA Nexus API. "
            "IDA command-line switches follow a -- separator."
        ),
    )
    parser.add_argument(
        "input", nargs="?", type=Path, help="Executable or existing IDB to open"
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Initialize idalib without opening a database, then exit",
    )
    add_lifecycle_arguments(parser)
    parser.epilog = "IDA command-line switches after -- are passed to idalib unchanged."
    return parser


def _split_switches(argv: list[str]) -> tuple[list[str], list[str]]:
    """Separate the worker's own arguments from the IDA switches after ``--``."""
    if "--" not in argv:
        return argv, []
    index = argv.index("--")
    return argv[:index], argv[index + 1 :]


def probe() -> None:
    """Initialize idalib without opening a database."""
    importlib.import_module("ida_domain")


def _work_around_idapro_idausr_path_list() -> None:
    """Restrict IDAUSR to its primary directory for the worker process.

    Shipped idapro versions treat the entire IDAUSR search path as one directory
    when locating ida-config.json. IDA defines the first entry as its writable
    user directory, so use that entry until fixed idapro releases are ubiquitous.
    """
    idausr = os.environ.get("IDAUSR")
    if not idausr:
        return
    primary = idausr.split(os.pathsep, 1)[0]
    if primary:
        os.environ["IDAUSR"] = primary


def _redirect_output(record_suffix: str) -> Path:
    directory = ensure_private_directory(LOG_DIR)
    path = directory / f"{record_suffix}.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    if fd not in (1, 2):
        os.close(fd)
    # Re-wrap after dup2 so Python buffering does not hide startup failures.
    sys.stdout = os.fdopen(1, "w", buffering=1, closefd=False)
    sys.stderr = os.fdopen(2, "w", buffering=1, closefd=False)
    return path


def _log_database_state(event: str, path: Path, **details: Any) -> None:
    """Record file state at native lifecycle boundaries without reading IDB contents."""
    record = {"event": event, "time_ns": time.time_ns(), "path": str(path), **details}
    try:
        stat = path.stat()
        record.update(size=stat.st_size, modified_ns=stat.st_mtime_ns)
    except OSError as exc:
        record["stat_error"] = str(exc)
    print("[ida-nexus] " + json.dumps(record), flush=True)


def main(argv: list[str] | None = None) -> int:
    # This must happen before probe() imports idapro and reads ida-config.json.
    # It is process-local; the MCP server and its parent retain the full path.
    _work_around_idapro_idausr_path_list()

    parser = _parser()
    own_arguments, switches = _split_switches(
        list(sys.argv[1:] if argv is None else argv)
    )
    args = parser.parse_args(own_arguments)
    args.switches = switches
    if args.probe:
        if args.input is not None or switches:
            parser.error("input and IDA switches cannot be used with --probe")
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 -- idalib may raise arbitrary errors
            print(f"[ida-nexus] idalib initialization failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.input is None:
        parser.error("the following arguments are required: input")

    try:
        suffix = validate_record_suffix(args.record_suffix or os.urandom(3).hex())
    except ValueError as exc:
        print(f"[ida-nexus] {exc}", file=sys.stderr)
        return 2
    _redirect_output(suffix)

    try:
        validate_lease_grace(args.lease_grace)
    except ValueError as exc:
        print(f"[ida-nexus] {exc}", file=sys.stderr)
        return 2
    try:
        input_path = args.input.expanduser().resolve(strict=True)
    except FileNotFoundError:
        print(f"[ida-nexus] input does not exist: {args.input}", file=sys.stderr)
        return 2

    # Import ida-domain only after the process-specific log is installed. In
    # library mode it loads idapro first, which makes the IDAPython modules
    # available and records initialization failures in the worker log.
    probe()

    import ida_kernwin
    import ida_loader
    import idapro

    # serve()/stop_serving() are available in IDA 9.4+, but older idapro
    # stubs from the pinned ida-domain Git branch do not declare them.
    kernwin: Any = ida_kernwin
    # idalib suppresses native output by default. stdout/stderr already point
    # at this worker's private log, so keep initialization errors there too.
    idapro.enable_console_messages(True)

    session = NexusSession(
        backend="idalib",
        managed=args.managed,
        record_suffix=suffix,
        lease_grace=args.lease_grace,
        on_shutdown=kernwin.stop_serving,
    )
    server: Any = None
    opened = False
    stop_signal: int | None = None

    def request_stop(signum: int, frame: Any) -> None:
        nonlocal stop_signal
        stop_signal = signum
        kernwin.stop_serving()

    previous_handlers: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)

    phase = "opening"
    try:
        _log_database_state(
            "database.open_started",
            input_path,
            ida_version=idapro.get_library_version(),
            switches=list(args.switches),
        )
        # Analysis is deferred (-a) so Nexus can publish first and advance it
        # in background slices; an explicit wait later enables ongoing analysis.
        status = idapro.open_database(
            str(input_path), False, join_ida_switches(args.switches)
        )
        if status != 0:
            raise RuntimeError(f"idalib failed to open {input_path} (status {status})")
        opened = True
        _disarm_startup_cleanup()
        phase = "initializing"
        _log_database_state("database.opened", input_path)
        if args.save_after_open:
            # IDA repaired an unpacked database; make sure a packed base exists.
            save_current_database()
        server = session.start(autoanalysis=args.auto_analysis)
        print(f"[ida-nexus] {server.url}", flush=True)
        phase = "serving"

        # In IDA 9.4+, serve() dispatches execute_sync requests from HTTP
        # threads until managed lease shutdown or a signal calls
        # stop_serving(). A signal received during database startup must not be
        # lost before the serve loop begins.
        if stop_signal is None:
            kernwin.serve()
        return 128 + stop_signal if stop_signal is not None else 0
    except Exception as exc:  # noqa: BLE001 -- IDA initialization is third-party code
        _log_database_state(
            "database.worker_failed",
            input_path,
            phase=phase,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        print(f"[ida-nexus] {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        session.stop()
        if opened:
            # We are back on the idalib main thread after serve(). A remote
            # exclusive shutdown may explicitly request that changes be discarded.
            save = server.save_on_shutdown if server is not None else True
            closing_path = Path(
                ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or input_path
            )
            _log_database_state("database.close_started", closing_path, save=save)
            try:
                idapro.close_database(save)
                _log_database_state("database.closed", closing_path, save=save)
            except Exception as exc:  # noqa: BLE001 -- SWIG may raise arbitrary errors
                print(
                    f"[ida-nexus] failed to close database: {exc}",
                    file=sys.stderr,
                )
        # The lifetime lock is deliberately released only after the IDB close.
        session.release()
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    raise SystemExit(main())
