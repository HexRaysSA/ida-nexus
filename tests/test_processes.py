import subprocess
import sys

from ida_nexus._processes import wait_process_exit


def test_wait_for_full_process_exit():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.3)"])
    try:
        assert not wait_process_exit(child.pid, timeout=0)
        assert wait_process_exit(child.pid, timeout=3)
    finally:
        child.wait(timeout=3)
