"""A generated cover password must never survive in state, argv or output."""
import base64
import copy
import subprocess
import unittest
from unittest.mock import patch
from node_state_test import VALUE
from node_config_test import HOST
import node_runtime

class CoverPasswordTest(unittest.TestCase):
    def test_password_is_384_random_bits_and_only_the_hash_is_saved(self):
        value=copy.deepcopy(VALUE);value['options']['cover']=True
        calls=[]
        def command(args, **kw):
            calls.append((args,kw))
            return subprocess.CompletedProcess(args,0,('$6$salt$'+'a'*86).encode(),b'')
        with patch.object(node_runtime,'command',command), patch.object(node_runtime.os,'urandom',return_value=b'X'*48) as random:
            node_runtime.Runtime(None,HOST).ensure_keys(value)
        random.assert_called_once_with(48)
        self.assertEqual(calls[0][0],['openssl','passwd','-6','-stdin'])
        self.assertEqual(len(calls[0][1]['data'].strip()),64)
        self.assertNotIn(base64.urlsafe_b64encode(b'X'*48).decode(),str(value))
        self.assertTrue(value['identity']['cover_auth'].startswith('$6$'))
        with patch.object(node_runtime,'command',side_effect=AssertionError('password must be stable')):
            node_runtime.Runtime(None,HOST).ensure_keys(value)

if __name__=='__main__':unittest.main()
