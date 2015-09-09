<?php

namespace Moccalotto\Crypto;

use RuntimeException;

class Bytes
{
    public static function random($count)
    {
        $result = openssl_random_pseudo_bytes($count, $secure);

        if (false === $result) {
            throw new RuntimeException('openssl_random_pseudo_bytes failed to generate random bytes');
        }

        if (false === $secure) {
            throw new RuntimeException('openssl_random_pseudo_bytes failed to generate secure randomness');
        }

        return $result;
    }

    public static function count($str)
    {
        return mb_strlen($str, '8bit');
    }

    public static function slice($str, $start, $length = null)
    {
        return mb_substr($str, $start, $length, '8bit');
    }
}
