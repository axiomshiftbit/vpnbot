<?php
require __DIR__ . '/managed_nodes_test.php';
class AtomicDatFixture extends ManagedFixtureBot {
    public string $directory;
    public function datDir(): string { return $this->directory; }
}
$bot = new AtomicDatFixture();
$bot->directory = sys_get_temp_dir().'/dat-cache-'.bin2hex(random_bytes(8)); mkdir($bot->directory, 0700);
$path = $bot->directory.'/sample.dat'; $failed = 0;
// Equal-sized valid GeoSite records; a download replaces the inode atomically.
$blob = static fn($name) => "\x0a\x12\x0a\x05".$name."\x12\x09\x08\x02\x12\x05a.com";
try {
    file_put_contents($path, $blob('alpha')); touch($path, 1700000000);
    $bot->datCategories('sample.dat'); $bot->datCategoryTypes('sample.dat');
    file_put_contents($path.'.new', $blob('bravo')); touch($path.'.new', 1700000000); rename($path.'.new', $path);
    foreach (['categories' => $bot->datCategories('sample.dat') === ['bravo'],
        'types' => $bot->datCategoryTypes('sample.dat') === ['bravo' => 'domain']] as $case => $ok) {
        echo ($ok ? 'PASS ' : 'FAIL ')."atomic same-size DAT replacement refreshes $case\n"; $failed += !$ok;
    }
} finally { unlink($path); rmdir($bot->directory); }
exit($failed ? 1 : 0);
