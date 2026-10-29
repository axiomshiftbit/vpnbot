import importlib.util
import os
from pathlib import Path
from subprocess import CompletedProcess
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('host_services',Path(__file__).resolve().parents[1]/'scripts/host_services.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)


class HostServicesTest(unittest.TestCase):
    def test_explicit_disposable_stand_does_not_change_host(self):
        with patch.dict(os.environ,{'VPNBOT_HOST_SERVICES':'off'}),patch.object(host,'run') as run:
            host.prepare(Path('/synthetic'));host.finalize(Path('/synthetic'))
            run.assert_not_called()

    def test_typo_is_not_a_silent_security_optout(self):
        with patch.dict(os.environ,{'VPNBOT_HOST_SERVICES':'of'}),self.assertRaises(RuntimeError):
            host.supported()

    def test_failed_guard_prevents_compose_preparation(self):
        with patch.object(host,'supported',return_value=True),patch.object(host.shutil,'which',return_value='/bin/tool'),patch.object(host,'same',return_value=False),patch.object(host,'run',return_value=CompletedProcess([],1)):
            with self.assertRaises(RuntimeError):host.prepare(Path('/synthetic'))

    def test_finalize_refuses_missing_firewall_for_existing_acme(self):
        with patch.object(host,'supported',return_value=True),patch.object(Path,'exists',return_value=True),patch.object(host,'run',side_effect=[CompletedProcess([],0),CompletedProcess([],1)]):
            with self.assertRaises(RuntimeError):host.finalize(Path('/synthetic'))

    def test_finalize_uses_non_disruptive_ensure(self):
        with patch.object(host,'supported',return_value=True),patch.object(host,'run',return_value=CompletedProcess([],0)) as run:
            host.finalize(Path('/synthetic'))
            self.assertEqual('ensure',run.call_args_list[-1].args[0][2])


if __name__=='__main__':unittest.main()
