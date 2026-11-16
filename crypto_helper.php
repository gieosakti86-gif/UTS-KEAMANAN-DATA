<?php
// crypto_helper.php

// Fungsi untuk membuat pasangan kunci RSA secara aman dan kompatibel
function getRsaKeys()
{
    $config = [
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];

    // Deteksi config openssl.cnf di Laragon
    $php_bin_dir = dirname(PHP_BINARY);
    $config_file = $php_bin_dir . '/extras/ssl/openssl.cnf';
    if (file_exists($config_file)) {
        $config["config"] = realpath($config_file);
    }

    $res = openssl_pkey_new($config);

    // Ekstrak Private Key dalam format string PEM
    openssl_pkey_export($res, $privKey, null, $config);

    // Ekstrak Public Key
    $pubKeyDetails = openssl_pkey_get_details($res);
    $pubKey = $pubKeyDetails["key"];

    return [$privKey, $pubKey];
}

// 1. ENKRIPSI HYBRID (Simetris + Asimetris)
function encryptContent($plainText)
{
    // Generate AES Key & IV
    $aesKey = openssl_random_pseudo_bytes(32);
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));

    // Enkripsi Simetris Konten
    $encryptedPayload = openssl_encrypt($plainText, 'aes-256-cbc', $aesKey, 0, $iv);

    // Dapatkan Kunci RSA
    list($privKey, $pubKey) = getRsaKeys();

    // Enkripsi Asimetris AES Key menggunakan Public Key
    openssl_public_encrypt($aesKey, $encryptedKey, $pubKey);

    return [
        'encrypted_payload' => $encryptedPayload,
        'iv'                => base64_encode($iv),
        'encrypted_key'     => base64_encode($encryptedKey),
        'private_key'       => base64_encode($privKey)
    ];
}

// 2. DEKRIPSI HYBRID (Asimetris + Simetris)
function decryptContent($encryptedPayload, $base64Iv, $base64EncryptedKey, $base64PrivKey)
{
    $iv = base64_decode($base64Iv);
    $encryptedKey = base64_decode($base64EncryptedKey);
    $privKey = base64_decode($base64PrivKey);

    // Ambil private key langsung sebagai string PEM
    $privateKey = openssl_get_privatekey($privKey);
    if (!$privateKey) {
        return "[Gagal Dekripsi: Private Key Tidak Valid]";
    }

    // Dekripsi Asimetris untuk membuka AES Key
    $decryptedAesKey = '';
    $success = openssl_private_decrypt($encryptedKey, $decryptedAesKey, $privateKey);

    if (!$success) {
        return "[Gagal Dekripsi: Kunci Privat Tidak Cocok]";
    }

    // Dekripsi Simetris Konten
    $decryptedContent = openssl_decrypt($encryptedPayload, 'aes-256-cbc', $decryptedAesKey, 0, $iv);

    return $decryptedContent !== false ? $decryptedContent : "[Gagal Dekripsi AES]";
}
