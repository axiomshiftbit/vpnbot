import fcntl
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TelemtSupervisorTest(unittest.TestCase):
    def test_saved_state_restart_lock_and_disable(self):
        # Настоящие процессы и flock; отдельное имя исключает pkill рабочего TeleMT.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'logs').mkdir()
            (root / 'telemt').mkdir()
            (root / 'public').write_text('fixture')
            name = 'tmtest' + str(os.getpid())
            core = root / 'core'
            core.write_text('#!/usr/bin/env python3\nimport ctypes,time\n'
                            f'ctypes.CDLL(None).prctl(15, b"{name}", 0, 0, 0)\n'
                            'while True: time.sleep(1)\n')
            core.chmod(0o700)
            script = (ROOT / 'scripts/start_telemt.sh').read_text()
            for old, new in [('/root/.ssh/authorized_keys', root / 'authorized'),
                             ('/ssh/key.pub', root / 'public'), ('ssh-keygen -A', 'true'),
                             ('/usr/sbin/sshd', 'true'), ('/telemt/', str(root / 'telemt') + '/'),
                             ('/logs', root / 'logs'), ('pgrep -x telemt', 'pgrep -x ' + name),
                             ('pkill -9 -x telemt', 'pkill -9 -x ' + name),
                             ('telemt run', str(core) + ' run')]:
                script = script.replace(old, str(new))
            config = root / 'telemt/telemt.toml'
            state = root / 'telemt/service-enabled'
            config.write_text('show_link = ["alice"]\n')

            def pids():
                result = subprocess.run(['pgrep', '-x', name], capture_output=True, text=True)
                alive = []
                for pid in result.stdout.split():
                    try:
                        if Path('/proc', pid, 'stat').read_text().split(') ')[1][0] != 'Z':
                            alive.append(int(pid))
                    except FileNotFoundError:
                        pass  # Процесс мог завершиться между pgrep и чтением stat.
                return alive

            def wait_for(predicate):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if predicate():
                        return
                    time.sleep(.05)
                self.fail('Супервизор не достиг ожидаемого состояния')

            with (root / 'logs/.lock.telemt').open('w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                process = subprocess.Popen(['sh', '-c', script], start_new_session=True,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    time.sleep(1.2)
                    self.assertEqual([], pids(), 'Запуск ждёт блокировку Bot::restartTelemt')
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    wait_for(lambda: len(pids()) == 1)  # Старый конфиг без нового флага.
                    first = pids()[0]
                    time.sleep(1.2)
                    self.assertEqual([first], pids(), 'Работающий процесс не дублируется')
                    # Ядро не должно удерживать общую блокировку после запуска.
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    os.kill(first, signal.SIGKILL)
                    wait_for(lambda: len(pids()) == 1 and pids()[0] != first)
                    state.write_text('0\n')
                    wait_for(lambda: not pids())
                    time.sleep(1.2)
                    self.assertEqual([], pids(), 'Отключённый сервис остаётся выключенным')
                    state.write_text('1\n')
                    wait_for(lambda: len(pids()) == 1)
                    state.write_text('invalid\n')
                    wait_for(lambda: not pids())
                    self.assertEqual('show_link = ["alice"]\n', config.read_text())
                    config.write_text('show_link = []\n')
                    state.write_text('1\n')
                    time.sleep(1.2)
                    self.assertEqual([], pids(), 'Без пользователей ядро не стартует')
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
