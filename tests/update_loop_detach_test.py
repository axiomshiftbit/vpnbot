#!/usr/bin/env python3
"""The background loop update/update.sh (protocol module apply, bot updates)
is started by `make preup`. Started from an interactive SSH session it shared
the terminal's session and died on logout (SIGHUP): after installing over SSH
the loop was gone until the next reboot, module toggles and the module apply
of a backup restore never ran. It must survive a terminal hangup."""
import os
from pathlib import Path
import pty
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UpdateLoopDetach(unittest.TestCase):
    def test_loop_survives_terminal_hangup(self):
        if not shutil.which('make') or not shutil.which('setsid'):
            self.skipTest('make/setsid not available')
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copy(ROOT/'makefile', work/'makefile')
            (work/'update').mkdir()
            # Stand-in for the loop: record its pid, then live for a while.
            (work/'update/update.sh').write_text('echo $$ > "$(dirname "$0")/stub_pid"\nexec sleep 30\n')
            pid, fd = pty.fork()
            if pid == 0:
                os.chdir(work)
                # The login shell leads the session and outlives make, as over SSH.
                os.execvp('sh', ['sh', '-c', 'make -s preup >/dev/null 2>&1; sleep 1'])
            os.waitpid(pid, 0)
            os.close(fd)            # terminal hangup, as on SSH logout
            deadline = time.time() + 5
            while not (work/'update/stub_pid').exists() and time.time() < deadline:
                time.sleep(.1)
            time.sleep(1)
            # No pid file: the hangup killed the loop before it even started.
            if not (work/'update/stub_pid').exists():
                alive = False
            else:
                stub = int((work/'update/stub_pid').read_text())
                try:
                    os.kill(stub, 0)
                    alive = True
                except ProcessLookupError:
                    alive = False
                finally:
                    try: os.kill(stub, signal.SIGTERM)
                    except ProcessLookupError: pass
            self.assertTrue(alive, 'update.sh died with the terminal session')


if __name__ == '__main__':
    unittest.main()
