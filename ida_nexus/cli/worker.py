import argparse
import importlib
import math
import os
import signal
import sys
from pathlib import Path
from typing import Any

from .._registry import (
    LOG_DIR,
    REGISTRY_DIR,
    InstanceIdentity,
    ensure_private_directory,
)
from .._runtime import (
    AnalysisState,
    IDARuntime,
    IdbChangeState,
    create_autoanalysis_hook,
    reconcile_autoanalysis_state,
)
from .._server import DEFAULT_LEASE_GRACE_SECONDS, NexusHTTPServer


def _parse_non_negative_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return parsed


def _parse_image_base(value: str) -> int:
    """Parse a byte-addressed image base for IDA's paragraph-based ``-b``."""

    image_base = _parse_non_negative_int(value)
    if image_base % 16:
        raise argparse.ArgumentTypeError("image base must be 16-byte aligned")
    return image_base


def _image_base_to_paragraphs(image_base: int | None) -> int | None:
    return image_base // 16 if image_base is not None else None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-nexus worker",
        description="Open one executable in idalib and expose the IDA Nexus API",
    )
    parser.add_argument(
        "input", nargs="?", type=Path, help="Executable or existing IDB to open"
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Initialize idalib without opening a database, then exit",
    )
    parser.add_argument(
        "--auto-analysis",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Start IDA autoanalysis in the background after publishing the worker",
    )
    parser.add_argument(
        "--image-base",
        type=_parse_image_base,
        help="Image base in bytes; must be 16-byte aligned (converted to IDA -b paragraphs)",
    )
    parser.add_argument(
        "--new-database",
        action="store_true",
        help="Discard an existing database and create a new one",
    )
    parser.add_argument(
        "--output-database",
        type=Path,
        help="Write a newly-created database to this path",
    )
    parser.add_argument("--compiler", help="Compiler identifier (-C)")
    parser.add_argument(
        "--first-pass-directive",
        action="append",
        default=[],
        help="First-pass IDA configuration directive (-d); repeatable",
    )
    parser.add_argument(
        "--second-pass-directive",
        action="append",
        default=[],
        help="Second-pass IDA configuration directive (-D); repeatable",
    )
    parser.add_argument("--disable-fpp", action="store_true")
    parser.add_argument("--entry-point", type=_parse_non_negative_int)
    parser.add_argument(
        "--jit-debugger",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument("--log-file", type=Path, help="IDA kernel log file")
    parser.add_argument("--disable-mouse", action="store_true")
    parser.add_argument("--plugin-options")
    parser.add_argument("--processor", help="IDA processor module name")
    parser.add_argument(
        "--db-compression",
        choices=("compress", "pack", "no_pack"),
    )
    parser.add_argument("--run-debugger")
    parser.add_argument("--load-resources", action="store_true")
    parser.add_argument("--script-file", type=Path)
    parser.add_argument("--script-arg", action="append", default=[])
    parser.add_argument("--file-type", help="IDA loader/file type (-T value)")
    parser.add_argument("--file-member", help="Archive member for --file-type")
    parser.add_argument("--empty-database", action="store_true")
    parser.add_argument("--windows-dir", type=Path)
    parser.add_argument("--no-segmentation", action="store_true")
    debug_group = parser.add_mutually_exclusive_group()
    debug_group.add_argument("--debug-mask", type=_parse_non_negative_int)
    debug_group.add_argument("--debug-flag", action="append", default=[])
    parser.add_argument(
        "--managed",
        action="store_true",
        help="Exit after the last Nexus client lease is released",
    )
    parser.add_argument(
        "--record-suffix",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--lease-grace",
        type=float,
        default=DEFAULT_LEASE_GRACE_SECONDS,
        help=argparse.SUPPRESS,
    )
    return parser


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


def _redirect_output(record_id: str) -> Path:
    directory = ensure_private_directory(LOG_DIR)
    path = directory / f"{record_id}.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    if fd not in (1, 2):
        os.close(fd)
    # Re-wrap after dup2 so Python buffering does not hide startup failures.
    sys.stdout = os.fdopen(1, "w", buffering=1, closefd=False)
    sys.stderr = os.fdopen(2, "w", buffering=1, closefd=False)
    return path


def _build_ida_options(args: argparse.Namespace, options_type: Any) -> Any:
    """Translate byte-oriented worker arguments into ``IdaCommandOptions``."""

    return options_type(
        # idalib's run_auto_analysis=True blocks Database.open() until analysis
        # finishes. Always defer there so Nexus can publish first; the worker
        # starts the same wait operation asynchronously after registration.
        auto_analysis=False,
        loading_address=_image_base_to_paragraphs(args.image_base),
        new_database=args.new_database,
        compiler=args.compiler,
        first_pass_directives=args.first_pass_directive,
        second_pass_directives=args.second_pass_directive,
        disable_fpp=args.disable_fpp,
        entry_point=args.entry_point,
        jit_debugger=args.jit_debugger,
        log_file=(str(args.log_file.expanduser().resolve()) if args.log_file else None),
        disable_mouse=args.disable_mouse,
        plugin_options=args.plugin_options,
        output_database=(
            str(args.output_database.expanduser().resolve())
            if args.output_database
            else None
        ),
        processor=args.processor,
        db_compression=args.db_compression,
        run_debugger=args.run_debugger,
        load_resources=args.load_resources,
        script_file=(
            str(args.script_file.expanduser().resolve()) if args.script_file else None
        ),
        script_args=args.script_arg,
        file_type=args.file_type,
        file_member=args.file_member,
        empty_database=args.empty_database,
        windows_dir=(
            str(args.windows_dir.expanduser().resolve()) if args.windows_dir else None
        ),
        no_segmentation=args.no_segmentation,
        debug_flags=(
            args.debug_mask if args.debug_mask is not None else args.debug_flag
        ),
    )


def main(argv: list[str] | None = None) -> int:
    # This must happen before probe() imports idapro and reads ida-config.json.
    # It is process-local; the MCP server and its parent retain the full path.
    _work_around_idapro_idausr_path_list()

    parser = _parser()
    args = parser.parse_args(argv)
    if args.file_member and not args.file_type:
        parser.error("--file-member requires --file-type")
    if args.script_arg and not args.script_file:
        parser.error("--script-arg requires --script-file")
    if args.probe:
        if args.input is not None:
            parser.error("input cannot be used with --probe")
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 -- idalib may raise arbitrary errors
            print(f"[ida-nexus] idalib initialization failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.input is None:
        parser.error("the following arguments are required: input")

    suffix = args.record_suffix or os.urandom(3).hex()
    if len(suffix) != 6 or any(c not in "0123456789abcdef" for c in suffix):
        print("[ida-nexus] invalid record suffix", file=sys.stderr)
        return 2
    record_id = f"{os.getpid()}-{suffix}"
    _redirect_output(record_id)

    if not math.isfinite(args.lease_grace) or args.lease_grace < 0:
        print(
            "[ida-nexus] lease grace must be a finite non-negative number",
            file=sys.stderr,
        )
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
    import ida_nalt
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    # serve()/stop_serving() are available in IDA 9.4+, but older idapro
    # stubs from the pinned ida-domain Git branch do not declare them.
    kernwin: Any = ida_kernwin

    analysis_state = AnalysisState()
    analysis_hook: Any | None = None
    # The change hook is installed only while /idb_events has subscribers and
    # only after initial autoanalysis has finished.
    idb_change_state = IdbChangeState()
    database: Any | None = None
    runtime: IDARuntime | None = None
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
        options = _build_ida_options(args, IdaCommandOptions)
        database = Database.open(
            str(input_path),
            args=options,
            save_on_close=True,
        )
        # Non-empty IDA command options make idalib reinitialize its kernel.
        # Create and install Python hooks only after that cycle has completed.
        analysis_hook = create_autoanalysis_hook(analysis_state)
        analysis_hook.hook()
        reconcile_autoanalysis_state(analysis_state)

        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
        exe_path = ida_nalt.get_input_file_path() or str(input_path)
        idb_path = str(Path(idb_path).resolve()) if idb_path else ""
        exe_path = str(Path(exe_path).resolve()) if exe_path else ""
        identity = InstanceIdentity(
            idb_path=idb_path,
            exe_path=exe_path,
            backend="idalib",
            managed=args.managed,
        )
        runtime = IDARuntime(
            backend="idalib",
            database=database,
            analysis_state=analysis_state,
            idb_change_state=idb_change_state,
        )
        server = NexusHTTPServer(
            runtime,
            identity,
            analysis_state,
            REGISTRY_DIR,
            record_suffix=suffix,
            lease_grace=args.lease_grace,
            on_shutdown=kernwin.stop_serving,
        )
        server.start()
        if args.auto_analysis:
            server.start_autoanalysis()
        print(f"[ida-nexus] {server.url}", flush=True)

        # In IDA 9.4+, serve() dispatches execute_sync requests from HTTP
        # threads until managed lease shutdown or a signal calls
        # stop_serving(). A signal received during database startup must not be
        # lost before the serve loop begins.
        if stop_signal is None:
            kernwin.serve()
        return 128 + stop_signal if stop_signal is not None else 0
    except Exception as exc:  # noqa: BLE001 -- IDA initialization is third-party code
        print(f"[ida-nexus] {exc}", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.stop()
        # IDAPython TESTABLE_BUILD requires user hooks to be gone before kernel
        # or database teardown. In release builds this also avoids relying on
        # IDAPython's forced stale-hook cleanup.
        if analysis_hook is not None:
            try:
                analysis_hook.unhook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG hook cleanup
                print(
                    f"[ida-nexus] failed to remove analysis hook: {exc}",
                    file=sys.stderr,
                )
        if runtime is not None:
            try:
                # Ensure the lazily-installed hook is gone before teardown.
                runtime.disable_idb_change_hook()
            except Exception as exc:  # noqa: BLE001 -- best-effort SWIG hook cleanup
                print(
                    f"[ida-nexus] failed to remove idb-change hook: {exc}",
                    file=sys.stderr,
                )
        if (
            database is not None
            and runtime is not None
            and runtime.database is not None
        ):
            try:
                # We are back on the idalib main thread after serve(). A remote
                # exclusive shutdown may explicitly request that changes be discarded.
                save = getattr(server, "save_on_shutdown", True)
                database.close(save=save)
                runtime.database = None
            except Exception as exc:  # noqa: BLE001 -- SWIG may raise arbitrary errors
                print(
                    f"[ida-nexus] failed to close database: {exc}",
                    file=sys.stderr,
                )
        elif database is not None and runtime is None:
            try:
                database.close(save=True)
            except Exception as exc:  # noqa: BLE001 -- best-effort startup cleanup
                print(
                    f"[ida-nexus] failed to close database: {exc}",
                    file=sys.stderr,
                )
        # The lifetime lock is deliberately released only after the IDB close.
        if server is not None:
            server.release_registration()
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    raise SystemExit(main())
