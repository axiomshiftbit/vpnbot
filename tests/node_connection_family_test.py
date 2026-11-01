import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from node_state_test import VALUE
import node_runtime
from node_config_test import HOST

class NodeConnectionFamilyTest(unittest.TestCase):
    def test_missing_connection_address_is_rejected_before_runtime_files(self):
        value=copy.deepcopy(VALUE);value['options']['connect_family']=6
        with tempfile.TemporaryDirectory() as temp:
            store=SimpleNamespace(load=lambda _generation:value,path=lambda _generation:Path(temp))
            runtime=node_runtime.Runtime(store,HOST|{'public6':''})
            with patch.object(runtime,'write_runtime') as write, self.assertRaises(ValueError):
                runtime.prepare('a'*32)
            write.assert_not_called()

if __name__=='__main__':unittest.main()
