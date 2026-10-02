<?php
// Ключи создаются только во время теста, в репозиторий попадают лишь команды.
function backupPkiFixture(): array
{
    $caKey = openssl_pkey_new(['private_key_bits'=>2048]);
    $caCsr = openssl_csr_new(['commonName'=>'Synthetic backup CA'],$caKey);
    $ca = openssl_csr_sign($caCsr,null,$caKey,2);
    $serverKey = openssl_pkey_new(['private_key_bits'=>2048]);
    $serverCsr = openssl_csr_new(['commonName'=>'Synthetic backup server'],$serverKey);
    $server = openssl_csr_sign($serverCsr,$ca,$caKey,2);
    openssl_x509_export($ca,$caPem);openssl_pkey_export($caKey,$caPrivate);
    openssl_x509_export($server,$serverPem);openssl_pkey_export($serverKey,$serverPrivate);
    return ['ca'=>$caPem,'ca_key'=>$caPrivate,'server'=>$serverPem,'key'=>$serverPrivate];
}
