"""Честная provenance source security rebuild, без подделки Go module version."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_assets as assets


class RebuildInventoryTest(unittest.TestCase):
    def test_native_dll_must_match_the_linked_cronet_module(self):
        original = assets.go_info
        def changed(data):
            info = original(data)
            for module in info['modules']:
                if module['name'] == 'github.com/sagernet/cronet-go/lib/windows_amd64':
                    module['version'] = 'v0.0.0-wrong'
            return info
        with patch.object(assets, 'go_info', side_effect=changed), self.assertRaisesRegex(ValueError, 'DLL/module'):
            assets.inventory(Path(__file__).resolve().parents[1])

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        directory = root/'singbox_windows/security-rebuild'
        directory.mkdir(parents=True)
        tags = 'with_clash_api,with_naive_outbound,with_purego'
        names = {'go.mod':'module github.com/sagernet/sing-box\n', 'go.sum':'synthetic checksums\n',
                 'Dockerfile':'FROM synthetic builder\n', 'DEFAULT_BUILD_TAGS_WINDOWS':tags+'\n', 'LDFLAGS':'-s -w\n'}
        for name, content in names.items():
            (directory/name).write_text(content)
        release = dict(version='1.14.4+vpnbot.security.20261115', build_kind='source_security_rebuild', rebuild=dict(
            source_version='1.14.4', source_url='https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v1.14.4',
            source_sha256='a'*64, source_commit='b'*40, go_version='1.27.4',
            inputs={n:hashlib.sha256(c.encode()).hexdigest() for n,c in names.items()}))
        info = dict(main=dict(name='github.com/sagernet/sing-box',version='(devel)'),compiler='1.27.4',
                    settings={'-tags':tags,'GOOS':'windows','GOARCH':'amd64','GOAMD64':'v1','CGO_ENABLED':'0'})
        return root, release, info, release['version'].encode()

    def test_devel_requires_explicit_complete_source_provenance(self):
        root, release, info, binary = self.fixture()
        self.assertEqual(assets.application_version(root,release,info,binary),'v1.14.4')
        self.assertEqual(info['main']['version'],'(devel)')
        for field in ('build_kind','rebuild'):
            bad=copy.deepcopy(release);bad.pop(field)
            with self.subTest(field=field),self.assertRaises(ValueError):
                assets.application_version(root,bad,info,binary)

    def test_version_features_compiler_and_inputs_are_bound(self):
        root, release, info, binary = self.fixture()
        for key,value in [('source_sha256',''),('source_commit',''),('source_url','https://example.invalid/source'),
                          ('source_version','1.14.3'),('go_version','1.26.10'),('inputs',{})]:
            bad=copy.deepcopy(release);bad['rebuild'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                assets.application_version(root,bad,info,binary)
        with self.assertRaises(ValueError):
            assets.application_version(root,release,info,b'other runtime version')
        info['settings']['-tags']='with_quic'
        with self.assertRaises(ValueError):
            assets.application_version(root,release,info,binary)

    def test_changed_rebuild_input_is_rejected(self):
        root, release, info, binary = self.fixture()
        (root/'singbox_windows/security-rebuild/go.sum').write_text('changed')
        with self.assertRaisesRegex(ValueError,'digest mismatch'):
            assets.application_version(root,release,info,binary)

    def test_upstream_release_still_requires_real_module_version(self):
        root, release, info, binary = self.fixture()
        info['main']['version']='v1.14.4'
        self.assertEqual(assets.application_version(root,dict(version='1.14.4'),info,binary),'v1.14.4')
        with self.assertRaises(ValueError):
            assets.application_version(root,release,info,binary)


if __name__ == '__main__':
    unittest.main()
