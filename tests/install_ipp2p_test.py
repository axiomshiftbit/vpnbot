import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallIpp2pTest(unittest.TestCase):
    def install(self, kernel, packages, **flags):
        source = (ROOT / 'scripts/init.sh').read_text()
        function = 'install_ipp2p() {' + source.split('install_ipp2p() {', 1)[1].split('\n}', 1)[0] + '\n}'
        with tempfile.TemporaryDirectory() as tmp:
            function = function.replace('/etc/modules-load.d', tmp)
            env = dict(os.environ, TEST_KERNEL=kernel, TEST_PACKAGES=packages, **flags)
            script = '''set -euo pipefail
uname() { printf '%s\\n' "$TEST_KERNEL"; }
dpkg-query() {
    if [ "${!#}" = 'linux-image-*' ]; then printf '%s\\n' "$TEST_PACKAGES";
    elif [ "${!#}" = "${TEST_INSTALLED_HEADERS:-}" ]; then printf installed;
    else return 1; fi
}
apt-cache() { [ "$2" != "${TEST_MISSING_META:-}" ]; }
apt() { printf 'APT %s\\n' "$*"; [ "${TEST_APT_FAIL:-0}" = 0 ]; }
dkms() { printf 'DKMS %s\\n' "$*"; [ "${TEST_DKMS_FAIL:-0}" = 0 ]; }
modprobe() { printf 'MODPROBE %s\\n' "$*"; [ "${TEST_MODPROBE_FAIL:-0}" = 0 ]; }
''' + function + '\ninstall_ipp2p\n'
            p = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
            autoload = Path(tmp) / 'vpnbot-ipp2p.conf'
            return p, autoload.read_text() if autoload.exists() else None

    def test_debian_current_and_future_headers(self):
        p, autoload = self.install('6.12.111+deb13-amd64',
                                  'linux-image-amd64:amd64 installed\nlinux-image-6.12.111+deb13-amd64 installed\nlinux-image-6.12.90+deb13-amd64 config-files')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('APT install -y --no-install-recommends xtables-addons-common xtables-addons-dkms linux-headers-6.12.111+deb13-amd64 linux-headers-amd64\n', p.stdout)
        self.assertIn('DKMS autoinstall -k 6.12.111+deb13-amd64', p.stdout)
        self.assertEqual(autoload, 'xt_ipp2p\n')

    def test_debian_cloud_keeps_cloud_branch(self):
        p, _ = self.install('6.12.111+deb13-cloud-amd64', 'linux-image-cloud-amd64 installed')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('linux-headers-cloud-amd64', p.stdout)
        self.assertNotIn('linux-headers-amd64', p.stdout)

    def test_ubuntu_hwe_keeps_hwe_branch(self):
        p, _ = self.install('6.17.0-23-generic', 'linux-image-generic-hwe-24.04 installed\nlinux-image-6.17.0-23-generic installed')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('linux-headers-6.17.0-23-generic linux-headers-generic-hwe-24.04', p.stdout)
        self.assertNotIn('linux-headers-generic\n', p.stdout)

    def test_exact_headers_without_a_meta_package(self):
        p, _ = self.install('6.8.0-139-generic', 'linux-image-6.8.0-139-generic installed')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('linux-headers-6.8.0-139-generic\n', p.stdout)

    def test_existing_meta_is_not_upgraded_and_cannot_pull_a_new_kernel(self):
        p, _ = self.install('6.8.0-139-generic', 'linux-image-generic installed',
                            TEST_INSTALLED_HEADERS='linux-headers-generic')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('linux-headers-6.8.0-139-generic\n', p.stdout)
        self.assertNotIn('linux-headers-generic', p.stdout)

    def test_unavailable_meta_does_not_replace_running_kernel(self):
        p, _ = self.install('6.8.0-139-generic', 'linux-image-custom installed', TEST_MISSING_META='linux-headers-custom')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn('linux-headers-custom', p.stdout)

    def test_missing_current_headers_stops_installation(self):
        p, autoload = self.install('custom-kernel', '', TEST_APT_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('custom-kernel', p.stderr)
        self.assertNotIn('DKMS', p.stdout)
        self.assertIsNone(autoload)

    def test_failed_build_does_not_claim_module_is_ready(self):
        p, autoload = self.install('6.12-test', '', TEST_DKMS_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('MODPROBE', p.stdout)
        self.assertIsNone(autoload)

    def test_signature_or_module_load_failure_is_reported(self):
        p, autoload = self.install('6.12-test', '', TEST_MODPROBE_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('политику подписи', p.stderr)
        self.assertIsNone(autoload)


if __name__ == '__main__':
    unittest.main()
