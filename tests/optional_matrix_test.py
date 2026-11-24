import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'integration/fixtures/tests'))
import optional_matrix as matrix


class OptionalProfileResults(unittest.TestCase):
    def test_every_client_and_transport_has_one_successful_result(self):
        required = matrix.expected_checks()
        legacy = 'mieru/native-3.38.1/restored-profile-UDP'
        self.assertIn(legacy, required)
        others = [{'name': name, 'ok': True} for name in sorted(required - {legacy})]
        self.assertTrue(matrix.complete(others + [{'name': legacy, 'ok': True}]))
        for last in ([], [others[0]], [{'name': legacy, 'ok': False}], [{'name': 'unknown', 'ok': True}]):
            with self.subTest(last=last):
                self.assertFalse(matrix.complete(others + last))


if __name__ == '__main__':
    unittest.main()
