"""Регрессии прежних исправлений snolc остаются в патчах и выполняются при сборке образа."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Тест Rust -> исправление, которое он охраняет.
REGRESSIONS = {
    ('snolc-core.patch', 'crates/snolc/src/core_io.rs'): {
        'vpnbot_regression_datagram_waits_for_flush_without_duplicate_frames',  # vpnbot.2: последний UDP-кадр ждал в буфере
    },
    ('snolc-core.patch', 'crates/snolc/src/loader.rs'): {
        'vpnbot_only_transferred_bytes_keep_the_engine_busy',  # vpnbot.3: опрос в простое (CPU)
        'vpnbot_busy_worker_does_not_wake_idle_workers',
    },
    ('snolc-core.patch', 'crates/snolc/src/mux.rs'): {
        'vpnbot_open_precedes_data_after_another_stream_unblocks_the_writer',  # vpnbot.3: порядок кадров
        'vpnbot_dropped_stream_releases_receive_window',  # vpnbot.4: данные закрытого потока занимали окно
        'vpnbot_slow_reader_does_not_reset_session',  # vpnbot.4: медленный читатель рвал сессию
    },
    ('snolc-core.patch', 'crates/snolc/src/stack.rs'): {
        'vpnbot_regression_udp_peer_drop_releases_policy_flow',  # vpnbot.1: UDP после закрытия SOCKS5
        'vpnbot_udp_burst_waits_for_device_capacity_without_dropping',  # vpnbot.3: потеря кадров при полной очереди
    },
    ('snolc-modules.patch', 'modules/policy-local/src/lib.rs'): {
        'vpnbot_large_udp_refills_partial_credit_without_losing_accounting',  # vpnbot.3: голодание UDP у квоты
        'vpnbot_regression_udp_fin_closes_both_directions',
    },
}


def patched_tests(patch):
    """Имена #[test]-функций, добавленных патчем, по файлам."""
    found, current = {}, None
    for line in (ROOT / 'dockerfile' / patch).read_text().splitlines():
        if line.startswith('+++ b/'):
            current = line[6:]
        elif current and (match := re.match(r'\+\s*(?:async\s+)?fn (vpnbot_\w+)\(', line)):
            found.setdefault(current, set()).add(match[1])
    return found


class SnolcRegressionTests(unittest.TestCase):
    def test_regressions_stay_in_patches(self):
        for (patch, path), names in REGRESSIONS.items():
            with self.subTest(path=path):
                self.assertLessEqual(names, patched_tests(patch).get(path, set()))

    def test_image_build_runs_core_and_module_tests(self):
        dockerfile = (ROOT / 'dockerfile/snolc.dockerfile').read_text()
        server = dockerfile.split('AS server', 1)[1].split('\nFROM ', 1)[0]
        self.assertIn('cargo test --locked --release --workspace', server)
        modules = re.search(r'cargo test --locked --release ((?:-p \S+\s*\\?\s*)+)', server.split('WORKDIR /modules', 1)[1])
        self.assertIsNotNone(modules)
        self.assertIn('-p snolc-policy-local', modules[1])
        # Тесты не отфильтрованы по имени и не пропущены.
        self.assertNotRegex(server, r'cargo test[^\n]*(--skip|-- \w)')


if __name__ == '__main__':
    unittest.main()
