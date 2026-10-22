import math
import os
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TypedDict

from ._launch import (
    WorkerLaunchOptions,
    ida_command,
    ida_environment,
    select_host,
    worker_command,
)
from ._registry import (
    DEFAULT_TIMEOUT,
    LOG_DIR,
    SPAWN_DIR,
    DatabaseInstance,
    DiscoveredDatabase,
    FileLock,
    HostName,
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
class SpawnedWorker:
    """What a spawner hands back: the process plus how to recognize its record."""

    process: subprocess.Popen[bytes]
    log_path: Path
    record_suffix: str
    host: HostName = "idalib"


WorkerSpawner = Callable[
    [str, str, float, WorkerLaunchOptions],
    SpawnedWorker,
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


class _SpawnEnvironment(TypedDict, total=False):
    env: dict[str, str]
    cwd: str


def spawn_worker(
    source: str,
    expected_idb: str,
    lease_grace: float,
    options: WorkerLaunchOptions | None = None,
) -> SpawnedWorker:
    """Start the IDA process that will own ``expected_idb``.

    :func:`select_host` decides which executable runs. The idalib worker logs
    to ``logs/<suffix>.log`` itself; ``idat`` and ``ida`` are told to log there
    with ``-L`` unless the caller asked for its own IDA log file, which then
    doubles as the worker log.
    """
    options = options or WorkerLaunchOptions()
    host, executable = select_host(gui=options.gui)
    suffix = os.urandom(3).hex()
    log_path = ensure_private_directory(LOG_DIR) / f"{suffix}.log"
    # Left out entirely when unset, so the worker keeps inheriting this
    # process as it always has.
    spawn_environment: _SpawnEnvironment = {}
    if options.worker_env is not None:
        spawn_environment["env"] = dict(options.worker_env)
    if options.worker_cwd is not None:
        spawn_environment["cwd"] = options.worker_cwd

    hidden = True
    if executable is None:
        try:
            console_script = _find_console_script("ida-nexus")
        except FileNotFoundError as error:
            raise DatabaseOpenError(str(error)) from error
        command = worker_command(
            console_script,
            source,
            expected_idb,
            lease_grace,
            options,
            record_suffix=suffix,
        )
    else:
        if options.log_file:
            log_path = Path(options.log_file)
        command = ida_command(
            executable,
            host,
            source,
            expected_idb,
            lease_grace,
            options,
            record_suffix=suffix,
            log_path=log_path,
        )
        environment = ida_environment(
            options.worker_env if options.worker_env is not None else os.environ
        )
        if host == "idat":
            # IDA's text UI runs without a terminal only when told so.
            environment["TVHEADLESS"] = "1"
        else:
            hidden = False
        spawn_environment["env"] = environment

    popen_options: dict[str, Any] = dict(spawn_environment)
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        if hidden:
            creationflags |= subprocess.CREATE_NO_WINDOW
        popen_options["creationflags"] = creationflags
    else:
        popen_options["start_new_session"] = True
    process: Any = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=False,
        **popen_options,
    )
    return SpawnedWorker(process, log_path, suffix, host)


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
    spawned: SpawnedWorker, expected_idb: str, deadline: float
) -> DatabaseInstance:
    process, log_path, host = spawned.process, spawned.log_path, spawned.host
    expected_key = idb_key(expected_idb)
    # Launcher and worker PIDs may differ, and unrelated workers in different
    # PID namespaces may share a numeric PID. Only the random suffix passed
    # explicitly to the worker identifies this launch. The GUI plugin registers
    # on its own and never sees the suffix, so there the IDA process itself,
    # which we started directly, is the identity.
    record_suffix = spawned.record_suffix
    last_detail: str | None = None
    while True:
        now = time.monotonic()
        if now >= deadline:
            tail = _log_tail(log_path)
            message = f"timed out waiting for {host} worker {process.pid}"
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
            launched_by_us = entry.record_id.endswith(f"-{record_suffix}") or (
                host == "gui" and entry.pid == process.pid
            )
            if not launched_by_us:
                continue
            matched_record = True
            if entry.idb_key != expected_key:
                raise WorkerStartError(
                    f"worker {entry.pid} opened {entry.idb_path}, "
                    f"expected {expected_idb}"
                )
            if instance.state is InstanceState.READY:
                return entry
            last_detail = instance.detail

        returncode = process.poll()
        # uv/pip console-script launchers on Windows can exit successfully
        # after starting the real Python worker under a different PID. The
        # suffix remains authoritative, so keep waiting for its record.
        # idat and ida are started directly, so their exit is final.
        if (
            returncode is not None
            and not matched_record
            and (host != "idalib" or _launcher_exit_is_fatal(returncode, os.name))
        ):
            tail = _log_tail(log_path)
            message = f"{host} worker {process.pid} exited with status {returncode}"
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
    worker_env: Mapping[str, str] | None = None,
    worker_cwd: str | os.PathLike[str] | None = None,
    gui: bool = False,
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
    load_resources: bool = True,
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
    launch controls become IDA command-line switches for the spawned process.
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
        worker_env=worker_env,
        worker_cwd=os.fspath(worker_cwd) if worker_cwd is not None else None,
        gui=gui,
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
            raise FileNotFoundError(f"File not found: {source}")
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
        spawned = spawner(source, expected_idb, lease_grace, launch_options)
        return _await_ready(spawned, expected_idb, deadline)
    finally:
        spawn_lock.close()
