import json
import os
import sys
import sysconfig
from pathlib import Path


def _get_idausr_dir() -> Path:
    """Return IDA's main user directory."""
    idausr = os.environ.get("IDAUSR")
    if idausr:
        first = idausr.split(os.pathsep)[0].strip()
        if first:
            return Path(first).expanduser()

    if os.name == "nt":
        return Path(os.environ["APPDATA"]) / "Hex-Rays" / "IDA Pro"
    return Path.home() / ".idapro"


def get_state_dir() -> Path:
    """Return the directory where IDA Nexus state is stored."""
    state_dir = os.environ.get("IDA_NEXUS_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser()
    return _get_idausr_dir() / "nexus"


def _find_console_script(name: str) -> str:
    """Locate a pip-installed console script for the current interpreter.

    Inside IDA, ``sys.executable`` is the IDA binary, not a Python interpreter,
    so we cannot launch the worker with ``sys.executable -m ...``. The console
    script installed by pip carries the correct interpreter in its shebang (or is
    an ``.exe`` wrapper on Windows), so running it directly always works.

    Only script directories belonging to the current interpreter are searched.
    We never fall back to ``PATH``, which could resolve a same-named script from
    an unrelated environment running a different interpreter.

    Raises ``FileNotFoundError`` listing every path that was tried if *name*
    cannot be found.
    """
    dirs: list[str] = []
    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        dirs.append(scripts_dir)
    for prefix in dict.fromkeys([sys.prefix, sys.base_prefix]):
        dirs.append(os.path.join(prefix, "Scripts" if os.name == "nt" else "bin"))

    exe_names = [f"{name}.exe", name] if os.name == "nt" else [name]
    tried: list[str] = []
    for directory in dirs:
        for exe in exe_names:
            candidate = os.path.join(directory, exe)
            tried.append(candidate)
            if os.path.isfile(candidate):
                return candidate
    tried_list = "\n".join(f"  - {path}" for path in tried)
    raise FileNotFoundError(
        f"Could not find the {name!r} console script for this Python "
        f"interpreter. Tried:\n{tried_list}"
    )


STATE_DIR = get_state_dir()


def _idausr_dirs() -> list[Path]:
    """Every IDA user directory, in search order."""
    idausr = os.environ.get("IDAUSR")
    if idausr:
        found = [
            Path(entry.strip()).expanduser()
            for entry in idausr.split(os.pathsep)
            if entry.strip()
        ]
        if found:
            return found
    return [_get_idausr_dir()]


def find_ida_install_dir() -> Path | None:
    """Return IDA's installation directory the way the ``idapro`` package finds it.

    ``IDADIR`` wins; otherwise ``Paths.ida-install-dir`` from ``ida-config.json``
    in the primary user directory. Returns None when neither names a directory.
    """
    idadir = os.environ.get("IDADIR")
    if idadir:
        return Path(idadir).expanduser()
    config_path = _get_idausr_dir() / "ida-config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    paths = config.get("Paths") if isinstance(config, dict) else None
    value = paths.get("ida-install-dir") if isinstance(paths, dict) else None
    if isinstance(value, str) and value.strip():
        return Path(value).expanduser()
    return None


def find_ida_executable(name: str) -> Path | None:
    """Locate ``ida`` or ``idat`` inside the configured installation.

    Covers the flat Windows and Linux layouts and the macOS application bundle.
    """
    root = find_ida_install_dir()
    if root is None:
        return None
    for candidate in (
        root / f"{name}.exe",
        root / name,
        root / "Contents" / "MacOS" / name,
    ):
        if candidate.is_file():
            return candidate
    return None


NEXUS_PLUGIN_NAMES = ("ida-nexus", "ida-mcp")


def nexus_plugin_installed() -> bool:
    """Whether a plugin that depends on ida-nexus is installed for IDA.

    hcli installs a plugin's Python dependencies into IDA's own Python, so a
    present plugin means ``ida_nexus`` is importable inside ``ida`` and ``idat``.
    """
    return any(
        (directory / "plugins" / name / "ida-plugin.json").is_file()
        for directory in _idausr_dirs()
        for name in NEXUS_PLUGIN_NAMES
    )


def idalib_only() -> bool:
    """Operator opt-out: never start ``ida`` or ``idat``, only idalib workers."""
    value = os.environ.get("IDA_NEXUS_IDALIB_ONLY", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


BOOTSTRAP_SCRIPT = (
    Path(__file__).resolve().with_name("_bootstrap") / "ida_nexus_bootstrap.py"
)
