"""Внешние наборы не исчерпывают память PHP/конвертера и место под распаковку."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib

HELPER = Path(__file__).resolve().parents[1] / 'app/exit_ruleset.py'


class RulesetLimitsTests(unittest.TestCase):
    def normalize(self, body, fmt='srs'):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'input', Path(directory) / 'output'
            source.write_text(body)
            result = subprocess.run([sys.executable, str(HELPER), 'normalize', str(source), str(destination), fmt],
                                    capture_output=True, timeout=30)
            return result.returncode, destination.read_text() if destination.exists() else ''

    def test_srs_only_supported_fields_and_flat_rules(self):
        code, body = self.normalize(json.dumps({'rules': [
            {'domain': ['a.example'], 'domain_suffix': ['b.example'], 'ip_cidr': ['192.0.2.0/24'], 'port': [443]},
            {'domain_regex': ['^x'], 'domain_keyword': ['keyword']},
            {'type': 'logical', 'rules': [{'domain': ['ignored.example']}]},
        ]}))
        self.assertEqual(code, 0)
        rule = json.loads(body)['rules'][0]
        self.assertEqual(rule['domain'], ['a.example'])
        self.assertEqual(rule['ip_cidr'], ['192.0.2.0/24'])
        self.assertEqual(rule['domain_regex'], ['^x'])
        self.assertNotIn('port', rule)

    def test_bad_json_shapes_and_non_string_entries_fail(self):
        for value in ([], {}, {'rules': {}}, {'rules': [{'domain': 'a.example'}]},
                      {'rules': [{'domain': [{'unexpected': []}]}]}):
            with self.subTest(value=value):
                self.assertNotEqual(self.normalize(json.dumps(value))[0], 0)

    def test_entry_limit_before_php(self):
        self.assertNotEqual(self.normalize(json.dumps({'rules': [{'domain': ['a.example'] * 200001}]}))[0], 0)

    def test_decompressed_size_limit(self):
        self.assertNotEqual(self.normalize(' ' * (32 * 1024 * 1024 + 1))[0], 0)

    def test_normalized_size_limit(self):
        self.assertNotEqual(self.normalize(json.dumps({'rules': [{'domain_keyword': ['x' * (8 * 1024 * 1024)]}]}))[0], 0)

    def test_mrs_comments_and_wildcards_preserved(self):
        code, body = self.normalize('# comment\n +.example.org \n*.example.net\n\n', 'mrs')
        self.assertEqual((code, body), (0, '+.example.org\n*.example.net\n'))

    def test_mrs_entry_limit(self):
        self.assertNotEqual(self.normalize('example.org\n' * 200001, 'mrs')[0], 0)

    def test_converter_memory_limit(self):
        result = subprocess.run([sys.executable, str(HELPER), 'tool', sys.executable, '-c',
                                 'data=bytearray(512*1024*1024)'], capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)

    def test_converter_disk_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'output'
            result = subprocess.run([sys.executable, str(HELPER), 'tool', sys.executable, '-c',
                                     'import sys; f=open(sys.argv[1],"wb"); f.write(b"x"*(33*1024*1024))',
                                     str(destination)], capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertLessEqual(destination.stat().st_size, 32 * 1024 * 1024)

    @unittest.skipUnless(shutil.which('php') and shutil.which('sing-box'), 'нужен образ PHP с настоящим sing-box')
    def test_real_compressed_srs_does_not_kill_php_worker(self):
        # Валидный SRS < 1 МБ разворачивается в JSON > 40 МБ. Прежний код
        # завершал PHP с Allowed memory size exhausted до проверки числа правил.
        def varint(number):
            result = bytearray()
            while number >= 128:
                result.append((number & 127) | 128)
                number >>= 7
            result.append(number)
            return bytes(result)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'large.srs'
            compressor = zlib.compressobj()
            with source.open('wb') as stream:
                stream.write(b'SRS\x03')
                stream.write(compressor.compress(b'\x01\x00\x03' + varint(300000)))
                for index in range(300000):
                    value = ('%08x.%s.example.org' % (index, 'x' * 120)).encode()
                    stream.write(compressor.compress(varint(len(value)) + value))
                stream.write(compressor.compress(b'\xff\x00') + compressor.flush())
            result = subprocess.run(['php', '-d', 'memory_limit=128M', '-r',
                'require $argv[1]; $b=(new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();'
                '$r=$b->exitRulesetConvert(file_get_contents($argv[2]),"srs","domain");'
                'echo $r===null ? "REJECTED" : "ACCEPTED";',
                str(HELPER.parent / 'bot.php'), str(source)], capture_output=True, text=True, timeout=150)
            self.assertEqual(result.returncode, 0, result.stderr[-1000:])
            self.assertEqual(result.stdout, 'REJECTED')


if __name__ == '__main__':
    unittest.main()
