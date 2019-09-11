<?php

namespace Nymphaion\Crypto;

class Hash
{
    public static function password($value)
    {
        return password_hash($value, PASSWORD_BCRYPT, ['cost' => PASSWORD_BCRYPT_DEFAULT_COST]);
    }
}