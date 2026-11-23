"""The WARP probe verifies Cloudflare's certificate and refuses protocols older than TLS 1.2."""
from pathlib import Path
import ssl
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import node_warp_probe  # noqa: E402


class WarpProbeTls(unittest.TestCase):
    def test_context(self):
        context = node_warp_probe.tls_context()
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == '__main__':
    unittest.main()
