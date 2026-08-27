"""Standalone IDA Nexus plugin entry point."""

from typing import Any

import idaapi

import ida_nexus.plugin


class NexusPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Authenticated IDA Nexus HTTP API"
    help = ""
    wanted_name = "IDA Nexus"
    wanted_hotkey = ""

    def init(self) -> int:
        if not ida_nexus.plugin.init(owner="ida-nexus"):
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        ida_nexus.plugin.run(caller="ida-nexus")

    def term(self) -> None:
        ida_nexus.plugin.term()


def PLUGIN_ENTRY() -> NexusPlugin:
    # Always hand IDA an object: returning None makes the kernel complain that
    # "PLUGIN_ENTRY() must return an object!" on every non-GUI run. Declining is
    # init()'s job, via PLUGIN_SKIP, which IDA accepts silently.
    # IDA's SWIG stubs model plugin_t.__new__ with spurious arguments.
    plugin_type: Any = NexusPlugin
    return plugin_type()
