"""ocserv worker signal stack: the image applies the backport of upstream
996bc83e. With musl's constant 8 KiB SIGSTKSZ the kernel rejects sigaltstack
on CPUs with a large signal frame (AMX; seen on GitHub runners as
"sigaltstack: Out of memory"), the worker exits and clients get a TLS EOF."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OcservSigaltstackPatchTest(unittest.TestCase):
    def test_patch_is_applied_before_the_build(self):
        dockerfile = (ROOT / 'dockerfile/ocserv.dockerfile').read_text()
        self.assertIn('COPY dockerfile/ocserv-sigaltstack.patch /build-tools/ocserv-sigaltstack.patch', dockerfile)
        apply = dockerfile.index('patch -p1 < /build-tools/ocserv-sigaltstack.patch')
        self.assertLess(dockerfile.index('cd /tmp/ocserv-${OCSERV_VERSION}'), apply)
        self.assertLess(apply, dockerfile.index('meson setup build'))

    def test_patch_sizes_every_use_of_the_stack(self):
        patch = (ROOT / 'dockerfile/ocserv-sigaltstack.patch').read_text()
        self.assertTrue(patch.startswith('--- a/src/worker-misc.c\n+++ b/src/worker-misc.c\n'))
        self.assertIn('+#define MIN_SIGNAL_STACK_SIZE (64 * 1024)', patch)
        removed = [l for l in patch.splitlines() if l.startswith('-') and not l.startswith('---')]
        added = [l for l in patch.splitlines() if l.startswith('+') and not l.startswith('+++')]
        # posix_memalign, mprotect and ss_size all move from SIGSTKSZ to size.
        self.assertEqual(len([l for l in removed if 'SIGSTKSZ' in l]), 3)
        for line in ('+\tif (posix_memalign((void **)&ss.ss_sp, getpagesize(), size) != 0) {',
                     '+\tif (mprotect(ss.ss_sp, size, PROT_READ | PROT_WRITE) == -1) {', '+\tss.ss_size = size;'):
            self.assertIn(line, added)


if __name__ == '__main__':
    unittest.main()
