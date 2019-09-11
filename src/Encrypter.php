<?php

namespace Nymphaion\Crypto;

use Nymphaion\Crypto\Exceptions\DecryptException;
use Nymphaion\Crypto\Exceptions\EncryptException;

class Encrypter
{
    private $key;
    protected const ALGO = 'AES-128-CBC';

    public function __construct($key)
    {
        $this->key = (string)$key;
    }

    public static function generateKey()
    {
        return random_bytes(16);
    }

    public function encrypt(string $value): string
    {
        $iv = random_bytes(openssl_cipher_iv_length(static::ALGO));

        $value = openssl_encrypt($value, static::ALGO, $this->key, 0, $iv);

        if ($value === false) {
            throw new EncryptException('Encryption failed.');
        }

        return base64_encode(json_encode([
            'iv'    => base64_encode($iv),
            'value' => $value
        ]));
    }

    public function decrypt(string $payload): string
    {
        $payload = json_decode(base64_decode($payload));

        if ($payload === false || empty($payload['value']) || empty($payload['iv'])) {
            throw new DecryptException('Invalid payload.');
        }

        $decrypted = openssl_decrypt($payload['value'], static::ALGO, $this->key, 0, base64_decode($payload['iv']));

        if ($decrypted === false) {
            throw new DecryptException('Decryption failed.');
        }

        return $decrypted;
    }
}