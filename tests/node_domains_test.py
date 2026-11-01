import copy
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config as config
import node_cover
import node_runtime
from node_config_test import OPTIONS, HOST, KEYS


class NodeDomainsTest(unittest.TestCase):
    def test_aliases_are_validated_and_used_by_cover_and_reality(self):
        options = config.settings(OPTIONS | {'cover': True, 'domain': 'node.example.test',
            'domain_aliases': ['ALT.example.test', 'node.example.test', 'alt.example.test']})
        self.assertEqual(options['domain_aliases'], ['alt.example.test'])
        self.assertIn('server_name node.example.test alt.example.test;', node_cover.nginx(options, KEYS, True))
        core = config.core_config(options, HOST | {'cover_uid': 997}, KEYS)
        self.assertEqual(core['inbounds'][0]['streamSettings']['realitySettings']['serverNames'],
                         ['node.example.test', 'alt.example.test'])

    def test_alias_validation_rejects_injection_and_unbounded_lists(self):
        for aliases in ['example.test', ['https://example.test'], ['example.test;'], ['*.example.test'],
                        ['127.0.0.1'], ['x.example.test\nlisten 80;'], ['x.example.test']*33]:
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                config.settings(OPTIONS | {'domain_aliases': aliases})

    def test_real_certificate_checks_all_names_and_rejects_missing_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                '-nodes','-days','2','-subj','/CN=node.example.test','-addext',
                'subjectAltName=DNS:node.example.test,DNS:alt.example.test',
                '-keyout',str(root/'privkey.pem'),'-out',str(root/'fullchain.pem')],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            rt = node_runtime.Runtime(None, HOST)
            for name in ['node.example.test','alt.example.test']:
                rt.check_certificate(root, name)
            with self.assertRaises(RuntimeError): rt.check_certificate(root, 'missing.example.test')

    def test_bad_alias_dns_never_opens_acme_and_acme_failure_always_closes_it(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = node_runtime.Runtime(SimpleNamespace(root=Path(temp)), HOST)
            def answers(host, *_args, **_kwargs):
                return [(None,None,None,None,('127.0.0.1' if host.startswith('bad.') else HOST['public4'],80))]
            with patch.object(node_runtime.socket,'getaddrinfo',answers), patch.object(node_runtime,'command') as command:
                with self.assertRaises(ValueError): rt.certificate('node.example.test',['bad.example.test'])
                command.assert_not_called()
            calls=[]
            def command(args, **_kwargs):
                calls.append(list(map(str,args)))
                if args[0]=='certbot': raise RuntimeError('synthetic ACME failure')
                return subprocess.CompletedProcess(args,0,b'',b'')
            with patch.object(node_runtime.socket,'getaddrinfo',answers), patch.object(node_runtime,'command',command):
                with self.assertRaises(RuntimeError): rt.certificate('node.example.test',['alt.example.test'])
            self.assertEqual(calls[0][0:3],['nft','add','element'])
            self.assertEqual(calls[-1][0:3],['nft','delete','element'])
            names = [calls[1][n+1] for n,x in enumerate(calls[1]) if x=='-d']
            self.assertEqual(names,['node.example.test','alt.example.test'])


if __name__ == '__main__': unittest.main()
