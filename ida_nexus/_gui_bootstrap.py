"""IDA -S entry point: bootstrap the installed Nexus library after UI startup."""

import os
import signal

import ida_auto
import ida_kernwin
import idc

import ida_nexus.plugin

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def start():
    idc.batch(0)  # -A accepts loading defaults; the resulting GUI is interactive.
    ida_nexus.plugin.start()
    return -1


_timer = ida_kernwin.register_timer(100, start)
if "IDA_NEXUS_AUTO_ANALYSIS" in os.environ:
    ida_auto.enable_auto(os.environ["IDA_NEXUS_AUTO_ANALYSIS"] == "1")
