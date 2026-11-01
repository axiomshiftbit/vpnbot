<?php
require_once '/lab/app/ManagedNodeProfile.php';
try {
    $body = stream_get_contents(STDIN, 65537);
    if (strlen($body) > 65536) throw new RuntimeException('size');
    $profile = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
    echo json_encode(ManagedNodeProfile::parse($profile, $argv[1] ?? 'origin')['managed_outbound'], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    fwrite(STDERR, "profile rejected\n");
    exit(1);
}
