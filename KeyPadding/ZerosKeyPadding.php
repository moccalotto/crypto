<?php

namespace Moccalotto\Crypto\KeyPadding;

use Moccalotto\Crypto\KeyPaddingInterface;

class ZerosKeyPadding implements KeyPaddingInterface
{
    public function pad($key, $key_size)
    {
        $orig_length = strlen($key);
        $append = $key_size - $orig_length;

        if (0 === $append) {
            return $key;
        }

        if ($append < 0) {
            return substr($key, 0, $key_size);
        }

        return $key . str_repeat(chr(0), $append);
    }
}
