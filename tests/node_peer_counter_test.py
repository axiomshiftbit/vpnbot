"""Node-side accounting, durability and ordering of external peer resets."""
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import node_counters
import node_state


class PeerCounterTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = node_state.Store(directory.name)
        self.peer = {'id': str(uuid.uuid4()), 'name': 'panel', 'enabled': True}
        self.uid = node_counters.key(self.peer)
        self.raw = 120
        self.epoch = 'core-one'

    def read(self):
        return self.epoch, {'stat': [{'name': 'user>>>panel>>>traffic>>>uplink', 'value': str(self.raw)},
                                    {'name': 'user>>>controller>>>traffic>>>uplink', 'value': '1000'}]}

    def poll(self, peers=None):
        return node_counters.sample(self.store, [self.peer] if peers is None else peers, self.read)

    def reset(self, sequence):
        return node_counters.sample(self.store, [self.peer], self.read, self.uid, sequence)['result']

    def test_ack_loss_offline_restart_and_out_of_order(self):
        self.assertEqual(self.poll()[self.uid]['uplink'], 120)
        def offline(): raise ConnectionError()
        with self.assertRaises(ConnectionError):
            node_counters.sample(self.store, [self.peer], offline, self.uid, 4)
        self.assertEqual(self.poll()[self.uid]['sequence'], 0)
        self.assertEqual(self.reset(4), 'applied')
        self.store = node_state.Store(self.store.root)
        self.raw += 17
        self.assertEqual(self.reset(4), 'applied')
        self.assertEqual(self.poll()[self.uid]['uplink'], 17)
        self.assertEqual(self.reset(5), 'applied')
        self.epoch = 'core-two'; self.raw = 6
        self.assertEqual(self.reset(4), 'superseded')
        self.assertEqual(self.poll()[self.uid]['uplink'], 6)
        self.assertEqual(self.poll()[self.uid]['uplink'], 6)
        self.assertEqual((self.store.root / node_counters.FILE).stat().st_mode & 0o777, 0o600)

    def test_removal_rotation_wireguard_and_invalid_samples(self):
        self.poll()
        self.raw -= 1
        with self.assertRaises(ValueError): self.poll()
        self.raw += 2
        self.assertEqual(self.poll()[self.uid]['uplink'], 121)
        self.assertEqual(self.poll([dict(self.peer, channel='wireguard')]), {})
        self.assertEqual(node_counters.sample(self.store, [], self.read, self.uid, 1)['result'], 'removed')
        replacement = dict(self.peer, id=str(uuid.uuid4()), channel='amnezia')
        self.epoch = 'new-peer'; self.raw=7
        self.assertEqual(self.poll([replacement])[node_counters.key(replacement)]['uplink'], 7)
        self.assertEqual(node_counters.sample(self.store, [replacement], self.read, self.uid, 3)['result'], 'removed')
        for sequence in (0, -1, 2**53, True):
            with self.assertRaises(ValueError): self.reset(sequence)
        self.store.pending = lambda: {'pending': True}
        with self.assertRaises(ValueError): self.reset(8)
