import math
import os
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from ._registry import (
    DEFAULT_TIMEOUT,
    LOG_DIR,
    SPAWN_DIR,
    DatabaseInstance,
    DiscoveredDatabase,
    FileLock,
    InstanceState,
    canonical_path,
    ensure_private_directory,
    idb_key,
    scan_instances,
)
from .database_state import (
    _backup_unpacked_database,
    expected_idb_path,
    probe_database_state,
)
from .errors import (
    AmbiguousDatabaseError,
    DatabaseBusyError,
    DatabaseOpenError,
    NoDatabaseInstanceError,
    WorkerStartError,
)
from .paths import _find_console_script


@dataclass(frozen=True)
class WorkerLaunchOptions:
    """IDA import options used only when a new idalib worker is spawned."""

    auto_analysis: bool = True
    image_base: int | None = None
    new_database: bool = False
    compiler: str | None = None
    first_pass_directives: tuple[str, ...] = ()
    second_pass_directives: tuple[str, ...] = ()
    disable_fpp: bool = False
    entry_point: int | None = None
    jit_debugger: bool | None = None
    log_file: str | None = None
    disable_mouse: bool = False
    plugin_options: str | None = None
    processor: str | None = None
    db_compression: str | None = None
    run_debugger: str | None = None
    load_resources: bool = False
    script_file: str | None = None
    script_args: tuple[str, ...] = ()
    file_type: str | None = None
    file_member: str | None = None
    empty_database: bool = False
    windows_dir: str | None = None
    no_segmentation: bool = False
    debug_flags: int | tuple[str, ...] = 0
    save_after_open: bool = False

    def __post_init__(self) -> None:
        if self.image_base is not None:
            if isinstance(self.image_base, bool) or self.image_base < 0:
                raise ValueError("image_base must be a non-negative byte address")
            if self.image_base % 16:
                raise ValueError("image_base must be 16-byte aligned")
        if self.entry_point is not None and (
            isinstance(self.entry_point, bool) or self.entry_point < 0
        ):
            raise ValueError("entry_point must be a non-negative byte address")
        if self.db_compression not in {None, "compress", "pack", "no_pack"}:
            raise ValueError(
                "db_compression must be 'compress', 'pack', 'no_pack', or None"
            )
        if self.file_member and not self.file_type:
            raise ValueError("file_member requires file_type")
        if self.script_args and not self.script_file:
            raise ValueError("script_args require script_file")
        if isinstance(self.debug_flags, bool):
            raise TypeError("debug_flags must be an integer mask or flag names")
        if isinstance(self.debug_flags, int):
            if self.debug_flags < 0:
                raise ValueError("debug_flags mask must not be negative")
        elif any(not flag for flag in self.debug_flags):
            raise ValueError("debug flag names must not be empty")


WorkerSpawner = Callable[
    [str, str, float, WorkerLaunchOptions],
    tuple[subprocess.Popen[bytes], Path],
]


def _string_tuple(values: Sequence[str]) -> tuple[str, ...]:
    return (values,) if isinstance(values, str) else tuple(values)


def _single(
    instances: list[DiscoveredDatabase],
    description: str,
) -> DiscoveredDatabase | None:
    if not instances:
        return None
    if len(instances) > 1:
        records = ", ".join(item.instance.record_id for item in instances)
        raise AmbiguousDatabaseError(
            f"multiple live instances match {description}: {records}"
        )
    return instances[0]


def _resolve_existing(
    instances: list[DiscoveredDatabase],
    source: str,
    expected_idb: str,
) -> DatabaseInstance | None:
    # Match on the case-insensitive identity key, never the real (case-preserving)
    # path string: a GUI instance registered as Foo.exe.i64 must still match a
    # lookup spelled foo.exe.i64 on case-insensitive volumes.
    if not source.lower().endswith(".i64"):
        source_key = idb_key(source)
        gui = _single(
            [
                item
                for item in instances
                if item.instance.backend == "gui"
                and item.instance.exe_path
                and idb_key(item.instance.exe_path) == source_key
            ],
            f"executable {source}",
        )
        if gui is not None:
            if gui.state is InstanceState.READY:
                return gui.instance
            raise DatabaseBusyError(
                f"GUI instance {gui.instance.record_id} for {source} is unavailable: "
                f"{gui.detail or 'health probe failed'}"
            )

    expected_key = idb_key(expected_idb)
    owner = _single(
        [item for item in instances if item.instance.idb_key == expected_key],
        f"IDB {expected_idb}",
    )
    if owner is None:
        return None
    if owner.state is InstanceState.READY:
        return owner.instance
    raise DatabaseBusyError(
        f"instance {owner.instance.record_id} owns {expected_idb} but is unavailable: "
        f"{owner.detail or 'health probe failed'}"
    )


def _build_worker_command(
    source: str,
    expected_idb: str,
    lease_grace: float,
    options: WorkerLaunchOptions,
    *,
    launcher: Sequence[str],
    record_suffix: str,
) -> list[str]:
    """Build a worker command without starting a subprocess."""
    if not math.isfinite(lease_grace) or lease_grace < 0:
        raise ValueError("lease_grace must be a finite non-negative number")
    # A fresh database must be created from the original input, never by
    # reopening the old IDB that is about to be replaced.
    input_path = (
        source
        if options.new_database
        else expected_idb
        if os.path.exists(expected_idb)
        else source
    )
    if input_path == expected_idb and input_path != source:
        # Loader/import switches are baked into an existing IDB. Passing them
        # again can make IDA terminate with a fatal error (for example, -b may
        # be used only while loading a new file), so an existing database is
        # reopened without source-import configuration.
        # Autoanalysis is a worker lifecycle policy, not a source-import
        # option baked into the IDB. Preserve it while dropping loader flags.
        options = WorkerLaunchOptions(auto_analysis=options.auto_analysis)
    command = [
        *launcher,
        input_path,
        "--managed",
        "--record-suffix",
        record_suffix,
        "--lease-grace",
        str(lease_grace),
    ]
    default_idb = expected_idb_path(source)
    if (
        input_path == source
        and source != expected_idb
        and (options.new_database or expected_idb != default_idb)
    ):
        command.extend(["--output-database", expected_idb])
    if options.auto_analysis:
        command.append("--auto-analysis")
    else:
        command.append("--no-auto-analysis")
    if options.save_after_open:
        command.append("--save-after-open")
    if options.image_base is not None:
        command.extend(["--image-base", hex(options.image_base)])
    if options.new_database:
        command.append("--new-database")
    if options.compiler:
        command.append(f"--compiler={options.compiler}")
    command.extend(
        f"--first-pass-directive={directive}"
        for directive in options.first_pass_directives
    )
    command.extend(
        f"--second-pass-directive={directive}"
        for directive in options.second_pass_directives
    )
    if options.disable_fpp:
        command.append("--disable-fpp")
    if options.entry_point is not None:
        command.extend(["--entry-point", hex(options.entry_point)])
    if options.jit_debugger is not None:
        command.append(
            "--jit-debugger" if options.jit_debugger else "--no-jit-debugger"
        )
    if options.log_file:
        command.extend(["--log-file", options.log_file])
    if options.disable_mouse:
        command.append("--disable-mouse")
    if options.plugin_options:
        command.append(f"--plugin-options={options.plugin_options}")
    if options.processor:
        command.extend(["--processor", options.processor])
    if options.db_compression:
        command.extend(["--db-compression", options.db_compression])
    if options.run_debugger:
        command.append(f"--run-debugger={options.run_debugger}")
    if options.load_resources:
        command.append("--load-resources")
    if options.script_file:
        command.extend(["--script-file", options.script_file])
    command.extend(f"--script-arg={argument}" for argument in options.script_args)
    if options.file_type:
        command.extend(["--file-type", options.file_type])
    if options.file_member:
        command.extend(["--file-member", options.file_member])
    if options.empty_database:
        command.append("--empty-database")
    if options.windows_dir:
        command.extend(["--windows-dir", options.windows_dir])
    if options.no_segmentation:
        command.append("--no-segmentation")
    if isinstance(options.debug_flags, int):
        if options.debug_flags:
            command.extend(["--debug-mask", hex(options.debug_flags)])
    else:
        command.extend(f"--debug-flag={flag}" for flag in options.debug_flags)

    return command


def spawn_worker(
    source: str,
    expected_idb: str,
    lease_grace: float,
    options: WorkerLaunchOptions | None = None,
) -> tuple[subprocess.Popen[bytes], Path]:
    suffix = os.urandom(3).hex()
    try:
        executable = _find_console_script("ida-nexus")
    except FileNotFoundError as error:
        raise DatabaseOpenError(str(error)) from error
    command = _build_worker_command(
        source,
        expected_idb,
        lease_grace,
        options or WorkerLaunchOptions(),
        launcher=[executable, "worker"],
        record_suffix=suffix,
    )

    process: subprocess.Popen[bytes]
    if os.name == "nt":
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            ),
        )
    else:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            start_new_session=True,
        )
    log_path = ensure_private_directory(LOG_DIR) / f"{process.pid}-{suffix}.log"
    return process, log_path


def _log_tail(path: Path, limit: int = 16 * 1024) -> str:
    try:
        with path.open("rb") as file:
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(max(0, size - limit))
            return file.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _scan_until(
    deadline: float,
    *,
    probe_timeout: float = DEFAULT_TIMEOUT,
) -> list[DiscoveredDatabase]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("timed out scanning Nexus instances")
    return scan_instances(
        timeout=min(probe_timeout, remaining),
        deadline=deadline,
    )


def _launcher_exit_is_fatal(returncode: int, platform: str) -> bool:
    """Whether a launcher exit proves that no worker child can become ready."""

    return platform != "nt" or returncode != 0


def _await_ready(
    process: subprocess.Popen[bytes],
    expected_idb: str,
    log_path: Path,
    deadline: float,
) -> DatabaseInstance:
    expected_key = idb_key(expected_idb)
    # Windows console-script launchers may keep a wrapper PID while Python runs
    # the worker as a child. The random suffix is passed explicitly to that
    # worker and is therefore the stable launch identity across both processes.
    record_suffix = log_path.stem.rsplit("-", 1)[-1]
    last_detail: str | None = None
    actual_log_path = log_path
    while True:
        now = time.monotonic()
        if now >= deadline:
            tail = _log_tail(actual_log_path)
            message = f"timed out waiting for idalib worker {process.pid}"
            if last_detail:
                message += f": {last_detail}"
            if tail:
                message += f"\n\n{tail}"
            raise WorkerStartError(message)

        try:
            instances = _scan_until(
                deadline,
                probe_timeout=0.25,
            )
        except TimeoutError:
            # Let the top of the loop produce the worker-specific timeout with
            # any available startup log and last health detail.
            continue
        matched_record = False
        for instance in instances:
            entry = instance.instance
            launched_by_us = entry.pid == process.pid or entry.record_id.endswith(
                f"-{record_suffix}"
            )
            if not launched_by_us:
                continue
            matched_record = True
            actual_log_path = log_path.with_name(f"{entry.record_id}.log")
            if entry.idb_key != expected_key:
                raise WorkerStartError(
                    f"worker {entry.pid} opened {entry.idb_path}, "
                    f"expected {expected_idb}"
                )
            if instance.state is InstanceState.READY:
                return entry
            last_detail = instance.detail

        returncode = process.poll()
        if returncode is not None and not matched_record:
            matches = list(log_path.parent.glob(f"*-{record_suffix}.log"))
            if matches:
                actual_log_path = max(matches, key=lambda path: path.stat().st_mtime)
            # uv/pip console-script launchers on Windows can exit successfully
            # after starting the real Python worker under a different PID. The
            # suffix remains authoritative, so keep waiting for its record.
            if _launcher_exit_is_fatal(returncode, os.name):
                tail = _log_tail(actual_log_path)
                message = (
                    f"idalib worker launcher {process.pid} exited with status "
                    f"{returncode}"
                )
                if tail:
                    message += f"\n\n{tail}"
                raise WorkerStartError(message)

        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def resolve_instance(
    path: str | os.PathLike[str],
    *,
    spawn: bool = True,
    timeout: float = 120.0,
    lease_grace: float = 20.0,
    output_database: str | os.PathLike[str] | None = None,
    auto_analysis: bool = True,
    image_base: int | None = None,
    new_database: bool = False,
    compiler: str | None = None,
    first_pass_directives: Sequence[str] = (),
    second_pass_directives: Sequence[str] = (),
    disable_fpp: bool = False,
    entry_point: int | None = None,
    jit_debugger: bool | None = None,
    log_file: str | os.PathLike[str] | None = None,
    disable_mouse: bool = False,
    plugin_options: str | None = None,
    processor: str | None = None,
    db_compression: str | None = None,
    run_debugger: str | None = None,
    load_resources: bool = False,
    script_file: str | os.PathLike[str] | None = None,
    script_args: Sequence[str] = (),
    file_type: str | None = None,
    file_member: str | None = None,
    empty_database: bool = False,
    windows_dir: str | os.PathLike[str] | None = None,
    no_segmentation: bool = False,
    debug_flags: int | Sequence[str] = 0,
    spawner: WorkerSpawner = spawn_worker,
) -> DatabaseInstance:
    """Resolve one database owner, applying IDA options only when spawning.

    ``image_base`` uses byte units and must be 16-byte aligned. All remaining
    launch controls map directly to ``ida_domain.database.IdaCommandOptions``.
    """

    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive finite number")
    if not math.isfinite(lease_grace) or lease_grace < 0:
        raise ValueError("lease_grace must be a finite non-negative number")
    source = canonical_path(path)
    expected_idb = (
        canonical_path(output_database)
        if output_database is not None
        else expected_idb_path(source)
    )
    launch_options = WorkerLaunchOptions(
        auto_analysis=auto_analysis,
        image_base=image_base,
        new_database=new_database,
        compiler=compiler,
        first_pass_directives=_string_tuple(first_pass_directives),
        second_pass_directives=_string_tuple(second_pass_directives),
        disable_fpp=disable_fpp,
        entry_point=entry_point,
        jit_debugger=jit_debugger,
        log_file=os.fspath(log_file) if log_file is not None else None,
        disable_mouse=disable_mouse,
        plugin_options=plugin_options,
        processor=processor,
        db_compression=db_compression,
        run_debugger=run_debugger,
        load_resources=load_resources,
        script_file=os.fspath(script_file) if script_file is not None else None,
        script_args=_string_tuple(script_args),
        file_type=file_type,
        file_member=file_member,
        empty_database=empty_database,
        windows_dir=os.fspath(windows_dir) if windows_dir is not None else None,
        no_segmentation=no_segmentation,
        debug_flags=(
            debug_flags if isinstance(debug_flags, int) else _string_tuple(debug_flags)
        ),
    )
    deadline = time.monotonic() + timeout

    # Match a live instance before touching the filesystem: a registered
    # instance (e.g. an unsaved GUI database whose .i64 has not been written)
    # is valid even when the path does not exist. An explicit output path is a
    # request for that IDB identity, so do not attach to a GUI that merely has
    # the same input executable open under a different database path.
    instance = _resolve_existing(
        _scan_until(deadline),
        source if output_database is None else expected_idb,
        expected_idb,
    )
    if instance is not None:
        if new_database:
            raise DatabaseBusyError(
                f"cannot create a fresh database while instance "
                f"{instance.record_id} owns {expected_idb}"
            )
        return instance

    spawn_lock = FileLock(
        ensure_private_directory(SPAWN_DIR) / f"{idb_key(expected_idb)}.lock"
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"timed out resolving {expected_idb}")
    spawn_lock.acquire(remaining)
    try:
        instance = _resolve_existing(
            _scan_until(deadline),
            source if output_database is None else expected_idb,
            expected_idb,
        )
        if instance is not None:
            if new_database:
                raise DatabaseBusyError(
                    f"cannot create a fresh database while instance "
                    f"{instance.record_id} owns {expected_idb}"
                )
            return instance
        if not spawn:
            raise NoDatabaseInstanceError(expected_idb)
        if not os.path.exists(source):
            raise FileNotFoundError(source)
        file_state = probe_database_state(source, output_database=expected_idb)
        if file_state["state"] == "in_use":
            raise DatabaseBusyError(
                f"an unregistered IDA session owns {file_state['id0_path']}"
            )
        if file_state["state"] == "unknown":
            raise DatabaseOpenError(
                f"cannot safely open database with indeterminate unpacked state: "
                f"{file_state['error'] or file_state['id0_path']}"
            )
        if file_state["state"] in {"crashed", "unpacked"}:
            default_idb = expected_idb_path(source)
            if expected_idb != default_idb and not file_state["packed_database_exists"]:
                raise DatabaseOpenError(
                    "cannot automatically recover an unpacked database at a custom "
                    f"output path: {expected_idb}"
                )
        if file_state["state"] == "crashed":
            if new_database or file_state["packed_database_exists"]:
                try:
                    _backup_unpacked_database(file_state)
                except OSError as error:
                    raise DatabaseOpenError(
                        f"failed to preserve crashed database files: {error}"
                    ) from error
                after_backup = probe_database_state(
                    source,
                    output_database=expected_idb,
                )
                if after_backup["state"] == "in_use":
                    raise DatabaseBusyError(
                        f"an IDA session acquired {after_backup['id0_path']} "
                        "during crash recovery"
                    )
                if after_backup["state"] == "unknown":
                    raise DatabaseOpenError(
                        "database state became indeterminate during crash recovery: "
                        f"{after_backup['error'] or after_backup['id0_path']}"
                    )
            else:
                launch_options = replace(launch_options, save_after_open=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out resolving {expected_idb}")
        process, log_path = spawner(
            source,
            expected_idb,
            lease_grace,
            launch_options,
        )
        return _await_ready(process, expected_idb, log_path, deadline)
    finally:
        spawn_lock.close()
