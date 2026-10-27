"""IDA ``-S`` entry point: serve the database IDA just opened.

ida-nexus starts ``idat`` (or ``ida`` for ``gui=True``) with this script so the
worker runs in IDA's own Python, where the packages installed for plugins live.
Only the standard library and IDAPython are imported before ``ida_nexus`` is
found in that Python; a missing or outdated install is reported in IDA's log
and the process exits, so the client sees the reason instead of a timeout.
"""

import os

import ida_kernwin
import ida_pro
import idc

UPDATE_HINT = (
    "[ida-nexus] ida-nexus is missing or too old in IDA's Python: {error}\n"
    "[ida-nexus] Update the plugin: uvx ida-hcli plugin upgrade ida-nexus "
    "(or ida-mcp), or set IDA_NEXUS_IDALIB_ONLY=1 to keep using idalib workers."
)


def _main() -> None:
    # Native opening has succeeded. Do this before importing the installed
    # package: even a missing/broken Nexus plugin must not leave a usable GUI
    # eligible for extraction cleanup if it later crashes.
    guard = os.environ.get("IDA_NEXUS_STARTUP_GUARD")
    if guard is not None:
        try:
            os.unlink(guard)
        except FileNotFoundError:
            pass
        except OSError as error:
            print(f"[ida-nexus] cannot revoke startup cleanup: {error}", flush=True)
            ida_pro.qexit(1)
            return
        os.environ.pop("IDA_NEXUS_STARTUP_GUARD", None)
    try:
        from ida_nexus._session import run_bootstrap
    except Exception as error:  # noqa: BLE001 -- report any import failure
        print(UPDATE_HINT.format(error=error), flush=True)
        ida_pro.qexit(1)
        return
    code = run_bootstrap(list(idc.ARGV[1:]), interactive=ida_kernwin.is_idaq())
    if code is not None:
        ida_pro.qexit(code)


_main()
