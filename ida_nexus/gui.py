"""Public configuration for library-owned IDA GUI processes."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ._registry import LOG_DIR, ensure_private_directory
from .errors import DatabaseOpenError


@dataclass(frozen=True)
class GuiLaunchOptions:
    """Presentation environment supplied by the embedding host; no VNC dependency.

    Set executable for an explicit installation, or IDA_GUI_EXECUTABLE in the
    environment. Arguments are argv elements, never a shell command.
    """

    executable: str | None = None
    environment: dict[str, str] = field(default_factory=dict)

    def resolved_executable(self) -> str:
        candidate = (
            self.executable
            or os.environ.get("IDA_GUI_EXECUTABLE")
            or shutil.which("ida")
        )
        if not candidate or not Path(candidate).is_file():
            raise DatabaseOpenError(
                "Configure GuiLaunchOptions(executable=...) or IDA_GUI_EXECUTABLE"
            )
        return str(Path(candidate).resolve())


def spawn_gui(source, expected_idb, lease_grace, options, *, gui: GuiLaunchOptions):
    """Resolver spawner: start IDA directly and await its library bootstrap."""
    del lease_grace
    executable = gui.resolved_executable()
    existing = Path(expected_idb).is_file() and not options.new_database
    input_path = expected_idb if existing else source
    from ._resolver import WorkerLaunchOptions

    if existing:
        options = WorkerLaunchOptions(auto_analysis=options.auto_analysis)
    suffix = os.urandom(3).hex()
    log = ensure_private_directory(LOG_DIR) / f"gui-{suffix}.log"
    bootstrap = Path(__file__).with_name("_gui_bootstrap.py")
    args = [executable, "-A", f'-S"{bootstrap}"', f"-L{log}", "-P+"]
    if not options.auto_analysis:
        args.append("-a")
    if options.new_database:
        args.append("-c")
    if not existing and str(expected_idb) != str(source) + ".i64":
        args.append(f"-o{expected_idb}")
    for name, flag in [
        ("compiler", "C"),
        ("processor", "p"),
        ("plugin_options", "O"),
        ("run_debugger", "r"),
        ("windows_dir", "W"),
    ]:
        if value := getattr(options, name):
            args.append(f"-{flag}{value}")
    for name, flag in [
        ("disable_fpp", "f"),
        ("disable_mouse", "M"),
        ("load_resources", "R"),
        ("empty_database", "t"),
        ("no_segmentation", "x"),
    ]:
        if getattr(options, name):
            args.append(f"-{flag}")
    for name, flag in [("first_pass_directives", "d"), ("second_pass_directives", "D")]:
        args.extend(f"-{flag}{value}" for value in getattr(options, name))
    if options.image_base is not None:
        args.append(f"-b{options.image_base // 16:X}")
    if options.entry_point is not None:
        args.append(f"-i{options.entry_point:X}")
    if options.jit_debugger is not None:
        args.append(f"-I{int(options.jit_debugger)}")
    if options.file_type:
        args.append(
            f"-T{options.file_type}"
            + (f":{options.file_member}" if options.file_member else "")
        )
    if options.debug_flags:
        args.append(
            "-z"
            + (
                str(options.debug_flags)
                if isinstance(options.debug_flags, int)
                else ",".join(options.debug_flags)
            )
        )
    if options.db_compression:
        args.append(
            {"pack": "-P+", "compress": "-P", "no_pack": "-P-"}[options.db_compression]
        )
    if options.script_file:
        raise DatabaseOpenError(
            "GUI bootstrap owns -S; run startup Python through the returned handle"
        )
    env = {
        **os.environ,
        **gui.environment,
        "IDA_NEXUS_GUI_LAUNCHED": "1",
        "IDA_NEXUS_AUTO_ANALYSIS": "1" if options.auto_analysis else "0",
    }
    # Keep children independent of the initiating UI/MCP process.
    with log.open("ab") as output:
        process = subprocess.Popen(
            args + [str(input_path)],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=output,
            env=env,
            **(
                {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                if os.name == "nt"
                else {"start_new_session": True}
            ),
        )
    return process, log
