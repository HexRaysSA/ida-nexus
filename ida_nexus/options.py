"""Public options for opening or spawning an IDA Nexus database."""

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

MAX_KEEPALIVE_SECONDS = 3600.0


def _string_tuple(values: Sequence[str]) -> tuple[str, ...]:
    return (values,) if isinstance(values, str) else tuple(values)


@dataclass(frozen=True)
class DatabaseOpenOptions:
    """Attachment policy and spawn-only IDA import options.

    IDA import options configure only a newly spawned worker. They cannot
    reconfigure a reused GUI database or worker. ``auto_analysis`` controls
    whether that worker starts analysis asynchronously after publication
    (the default); an explicit ``wait_autoanalysis()`` can start it later
    either way.
    ``idle_timeout`` optionally releases only this client's managed-idalib
    lease after inactivity; it is ignored for GUI and unmanaged instances.
    ``keepalive`` instead delays worker shutdown after the lease is released.
    ``image_base`` is a byte address and must be 16-byte aligned.

    ``worker_env`` and ``worker_cwd`` configure the spawned process rather than
    the database it opens: without them the worker inherits the environment and
    working directory of whoever asked for the open. A caller that runs
    untrusted code through ``execute_python`` needs that inheritance to stop,
    because the worker's environment is readable from inside IDA. Pass a
    complete environment rather than an overlay; an empty mapping is honoured
    and gives the worker nothing.
    """

    spawn: bool = True
    startup_timeout: float = 120.0
    output_database: str | Path | None = None
    keepalive: float = 0.0
    idle_timeout: float | None = None
    worker_env: Mapping[str, str] | None = None
    worker_cwd: str | Path | None = None
    auto_analysis: bool = True
    image_base: int | None = None
    new_database: bool = False
    compiler: str | None = None
    first_pass_directives: tuple[str, ...] = ()
    second_pass_directives: tuple[str, ...] = ()
    disable_fpp: bool = False
    entry_point: int | None = None
    jit_debugger: bool | None = None
    log_file: str | Path | None = None
    disable_mouse: bool = False
    plugin_options: str | None = None
    processor: str | None = None
    db_compression: str | None = None
    run_debugger: str | None = None
    load_resources: bool = False
    script_file: str | Path | None = None
    script_args: tuple[str, ...] = ()
    file_type: str | None = None
    file_member: str | None = None
    empty_database: bool = False
    windows_dir: str | Path | None = None
    no_segmentation: bool = False
    debug_flags: int | tuple[str, ...] = 0

    def __post_init__(self) -> None:
        if not math.isfinite(self.startup_timeout) or self.startup_timeout <= 0:
            raise ValueError("startup_timeout must be a positive finite number")
        if (
            not math.isfinite(self.keepalive)
            or self.keepalive < 0
            or self.keepalive > MAX_KEEPALIVE_SECONDS
        ):
            raise ValueError(
                f"keepalive must be between 0 and {MAX_KEEPALIVE_SECONDS:g} seconds"
            )
        if self.idle_timeout is not None and (
            isinstance(self.idle_timeout, bool)
            or not isinstance(self.idle_timeout, (int, float))
            or not math.isfinite(self.idle_timeout)
            or self.idle_timeout <= 0
        ):
            raise ValueError("idle_timeout must be a positive finite number or None")
        if self.worker_env is not None:
            for name, value in self.worker_env.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise TypeError("worker_env names and values must be strings")
                # Rejected here rather than by the spawn, which reports a
                # ValueError from deep inside subprocess with no field name.
                if not name or "=" in name or "\0" in name:
                    raise ValueError(f"worker_env name is not usable: {name!r}")
                if "\0" in value:
                    raise ValueError(f"worker_env value for {name} contains a NUL")
        if self.worker_cwd is not None and not str(self.worker_cwd):
            raise ValueError("worker_cwd must not be empty")
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

        object.__setattr__(
            self,
            "first_pass_directives",
            _string_tuple(self.first_pass_directives),
        )
        object.__setattr__(
            self,
            "second_pass_directives",
            _string_tuple(self.second_pass_directives),
        )
        object.__setattr__(self, "script_args", _string_tuple(self.script_args))
        if self.worker_env is not None:
            object.__setattr__(
                self, "worker_env", MappingProxyType(dict(self.worker_env))
            )
        if not isinstance(self.debug_flags, int):
            object.__setattr__(self, "debug_flags", _string_tuple(self.debug_flags))
