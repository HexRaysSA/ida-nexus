"""Build IDA launches shared by the idalib worker, ``idat``, and the IDA GUI.

A database is always opened by IDA from command-line switches. The only thing
that differs between hosts is which executable receives them:

* ``idalib``: the ``ida-nexus worker`` console script of this interpreter hands
  the switches to ``idapro.open_database``. Used when no ida-nexus plugin is
  installed for IDA, or when ``IDA_NEXUS_IDALIB_ONLY`` is set.
* ``idat``: IDA's text-mode executable opens the database in IDA's own Python,
  so plugins find the packages installed for them. The bootstrap passed with
  ``-S`` serves it. Preferred whenever the plugin is installed.
* ``gui``: ``ida`` itself, for ``DatabaseOpenOptions(gui=True)``. The installed
  plugin registers the database as it does for any GUI session.
"""

from __future__ import annotations

import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ._registry import HostName
from .database_state import expected_idb_path, unpacked_database_paths
from .errors import DatabaseOpenError
from .paths import (
    BOOTSTRAP_SCRIPT,
    find_ida_executable,
    idalib_only,
    nexus_plugin_installed,
)

# Debug flag names accepted by DatabaseOpenOptions, as ida-domain spells them.
DEBUG_FLAGS = {
    "drefs": 0x00000001,
    "offsets": 0x00000002,
    "flirt": 0x00000004,
    "idp": 0x00000008,
    "ldr": 0x00000010,
    "plugin": 0x00000020,
    "ids": 0x00000040,
    "config": 0x00000080,
    "heap": 0x00000100,
    "licensing": 0x00000200,
    "demangler": 0x00000400,
    "queue": 0x00000800,
    "rollback": 0x00001000,
    "already_data_or_code": 0x00002000,
    "type_system": 0x00004000,
    "notifications": 0x00008000,
    "debugger": 0x00010000,
    "debugger_appcall": 0x00020000,
    "source_debugger": 0x00040000,
    "accessibility": 0x00080000,
    "network": 0x00100000,
    "stack_analysis": 0x00200000,
    "debug_info": 0x00400000,
    "lumina": 0x00800000,
}

_COMPRESSION_SWITCHES = {"compress": "-P+", "pack": "-P", "no_pack": "-P-"}


@dataclass(frozen=True)
class WorkerLaunchOptions:
    """Options used only when a new IDA process is spawned.

    Mostly IDA import options, which become IDA command-line switches.
    ``worker_env``, ``worker_cwd`` and ``gui`` are not: they configure the
    process itself.
    """

    worker_env: Mapping[str, str] | None = None
    worker_cwd: str | None = None
    gui: bool = False
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
    load_resources: bool = True
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
        if self.db_compression not in {None, *_COMPRESSION_SWITCHES}:
            raise ValueError(
                "db_compression must be 'compress', 'pack', 'no_pack', or None"
            )
        if self.file_member and not self.file_type:
            raise ValueError("file_member requires file_type")
        if isinstance(self.debug_flags, bool):
            raise TypeError("debug_flags must be an integer mask or flag names")
        if isinstance(self.debug_flags, int):
            if self.debug_flags < 0:
                raise ValueError("debug_flags mask must not be negative")
        else:
            unknown = [flag for flag in self.debug_flags if flag not in DEBUG_FLAGS]
            if unknown:
                raise ValueError(f"unknown debug flags: {', '.join(unknown)}")


def select_host(*, gui: bool) -> tuple[HostName, str | None]:
    """Decide which executable opens a new database, or fail with the reason.

    There is deliberately no fallback: a user who installed the plugin wants
    their plugins' packages, and an operator who set ``IDA_NEXUS_IDALIB_ONLY``
    wants nothing but idalib.
    """
    if gui:
        if idalib_only():
            raise DatabaseOpenError(
                "IDA_NEXUS_IDALIB_ONLY is set, so the IDA GUI cannot be started"
            )
        if not nexus_plugin_installed():
            raise DatabaseOpenError(
                "Opening in the IDA GUI needs the ida-nexus plugin installed for IDA: "
                "uvx ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus"
            )
        executable = find_ida_executable("ida")
        if executable is None:
            raise DatabaseOpenError(
                "The IDA GUI executable was not found; set IDADIR or ida-config.json"
            )
        return "gui", str(executable)
    if idalib_only() or not nexus_plugin_installed():
        return "idalib", None
    executable = find_ida_executable("idat")
    if executable is None:
        raise DatabaseOpenError(
            "The ida-nexus plugin is installed but idat was not found; set IDADIR "
            "or ida-config.json, or set IDA_NEXUS_IDALIB_ONLY=1 to use idalib"
        )
    return "idat", str(executable)


def plan_input(
    source: str, expected_idb: str, options: WorkerLaunchOptions
) -> tuple[str, WorkerLaunchOptions, str | None]:
    """Choose what IDA opens and which options still apply.

    Returns the input path, the options to pass, and the explicit output
    database when IDA must be told where to write a new one.
    """
    # A fresh database must be created from the original input, never by
    # reopening the old IDB that is about to be replaced.
    input_path = (
        source
        if options.new_database
        else expected_idb
        if os.path.exists(expected_idb)
        else source
    )
    if not options.new_database and (
        input_path == expected_idb or unpacked_database_paths(expected_idb)[0].exists()
    ):
        # Loader/import switches are baked into an existing IDB, packed or
        # unpacked. Passing them again makes IDA terminate with a fatal error
        # (-b and -R may be used only while loading a new file), so an existing
        # database is reopened without source-import configuration.
        # Autoanalysis and saving are worker lifecycle policy, not options
        # baked into the IDB, so they survive.
        options = WorkerLaunchOptions(
            worker_env=options.worker_env,
            worker_cwd=options.worker_cwd,
            gui=options.gui,
            auto_analysis=options.auto_analysis,
            save_after_open=options.save_after_open,
            load_resources=False,
        )
    output_database = None
    default_idb = expected_idb_path(source)
    if (
        input_path == source
        and source != expected_idb
        and (options.new_database or expected_idb != default_idb)
    ):
        output_database = expected_idb
    return input_path, options, output_database


def ida_switches(
    options: WorkerLaunchOptions,
    *,
    output_database: str | None,
    defer_analysis: bool,
) -> list[str]:
    """IDA command-line switches for these import options.

    ``defer_analysis`` disables analysis at load so the Nexus server can publish
    first and drive analysis in slices; the GUI instead analyzes in its own
    event loop and only gets ``-a`` when analysis was requested off.
    """
    switches: list[str] = []
    if defer_analysis or not options.auto_analysis:
        switches.append("-a")
    if options.image_base is not None:
        switches.append(f"-b{options.image_base // 16:X}")
    if options.new_database:
        # -o alone creates a database but refuses to replace an existing one.
        switches.append("-c")
    if options.compiler:
        switches.append(f"-C{options.compiler}")
    switches.extend(f"-d{directive}" for directive in options.first_pass_directives)
    switches.extend(f"-D{directive}" for directive in options.second_pass_directives)
    if options.disable_fpp:
        switches.append("-f")
    if options.entry_point is not None:
        switches.append(f"-i{options.entry_point:X}")
    if options.jit_debugger is not None:
        switches.append(f"-I{int(options.jit_debugger)}")
    if options.log_file:
        switches.append(f"-L{options.log_file}")
    if options.disable_mouse:
        switches.append("-M")
    if output_database is not None:
        switches.append(f"-o{output_database}")
    if options.plugin_options:
        switches.append(f"-O{options.plugin_options}")
    if options.processor:
        switches.append(f"-p{options.processor}")
    if options.db_compression:
        switches.append(_COMPRESSION_SWITCHES[options.db_compression])
    if options.run_debugger:
        switches.append(f"-r{options.run_debugger}")
    if options.load_resources:
        switches.append("-R")
    if options.file_type:
        file_type = options.file_type
        if options.file_member:
            file_type += f":{options.file_member}"
        switches.append(f"-T{file_type}")
    if options.empty_database:
        switches.append("-t")
    if options.windows_dir:
        switches.append(f"-W{options.windows_dir}")
    if options.no_segmentation:
        switches.append("-x")
    mask = (
        options.debug_flags
        if isinstance(options.debug_flags, int)
        else sum(DEBUG_FLAGS[flag] for flag in set(options.debug_flags))
    )
    if mask:
        switches.append(f"-z{mask:X}")
    return switches


def lifecycle_arguments(
    *,
    managed: bool,
    record_suffix: str,
    lease_grace: float,
    auto_analysis: bool,
    save_after_open: bool,
) -> list[str]:
    """Arguments the Nexus session parses inside IDA; never IDA switches."""
    if not math.isfinite(lease_grace) or lease_grace < 0:
        raise ValueError("lease_grace must be a finite non-negative number")
    arguments = ["--record-suffix", record_suffix, "--lease-grace", str(lease_grace)]
    if managed:
        arguments.append("--managed")
    arguments.append("--auto-analysis" if auto_analysis else "--no-auto-analysis")
    if save_after_open:
        arguments.append("--save-after-open")
    return arguments


def quote_ida_argument(value: str) -> str:
    """Quote one token the way IDA's own argument splitter expects.

    Matches ``IdaCommandOptions._quote`` in ida-domain: a switch keeps its two
    leading characters outside the quotes, as in ``-o"C:/my files/x.i64"``.
    """
    if not any(character in value for character in ' "\t'):
        return value
    prefix, body = "", value
    if value.startswith("-") and len(value) > 2:
        prefix, body = value[:2], value[2:]
    body = body.replace('"', '\\"')
    if body.endswith("\\"):
        body += "\\"
    return f'{prefix}"{body}"'


def join_ida_switches(switches: Sequence[str]) -> str:
    """The single string ``idapro.open_database`` takes instead of argv."""
    return " ".join(quote_ida_argument(switch) for switch in switches)


def script_switch(script: str | os.PathLike[str], arguments: Sequence[str]) -> str:
    """``-S"script arg ..."`` with IDA's quoting; IDA exposes it as ``idc.ARGV``.

    The whole value is one quoted argv element, so quotes that group a path or
    argument with spaces inside it are escaped once more.
    """
    parts = [quote_ida_argument(os.fspath(script))]
    parts.extend(quote_ida_argument(argument) for argument in arguments)
    return '-S"' + " ".join(part.replace('"', '\\"') for part in parts) + '"'


def worker_command(
    console_script: str,
    source: str,
    expected_idb: str,
    lease_grace: float,
    options: WorkerLaunchOptions,
    *,
    record_suffix: str,
) -> list[str]:
    """The ``ida-nexus worker`` command for the idalib host."""
    input_path, options, output_database = plan_input(source, expected_idb, options)
    return [
        console_script,
        "worker",
        input_path,
        *lifecycle_arguments(
            managed=True,
            record_suffix=record_suffix,
            lease_grace=lease_grace,
            auto_analysis=options.auto_analysis,
            save_after_open=options.save_after_open,
        ),
        "--",
        *ida_switches(options, output_database=output_database, defer_analysis=True),
    ]


def ida_command(
    executable: str,
    host: HostName,
    source: str,
    expected_idb: str,
    lease_grace: float,
    options: WorkerLaunchOptions,
    *,
    record_suffix: str,
    log_path: Path,
    bootstrap: str | os.PathLike[str] = BOOTSTRAP_SCRIPT,
) -> list[str]:
    """The ``idat`` or ``ida`` command: IDA opens the input, the bootstrap serves it.

    ``-A`` keeps load-time dialogs away; the bootstrap turns batch mode off again
    in the GUI. IDA logs to ``log_path`` unless the caller asked for its own
    kernel log, which then doubles as the worker log.
    """
    input_path, options, output_database = plan_input(source, expected_idb, options)
    command = [executable, "-A"]
    if not options.log_file:
        command.append(f"-L{log_path}")
    command.append(
        script_switch(
            bootstrap,
            lifecycle_arguments(
                managed=host != "gui",
                record_suffix=record_suffix,
                lease_grace=lease_grace,
                auto_analysis=options.auto_analysis,
                save_after_open=options.save_after_open,
            ),
        )
    )
    command.extend(
        ida_switches(
            options, output_database=output_database, defer_analysis=host != "gui"
        )
    )
    command.append(input_path)
    return command
