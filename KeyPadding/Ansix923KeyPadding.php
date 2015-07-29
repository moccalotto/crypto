<?php

namespace Moccalotto\Crypto\KeyPadding;

use Moccalotto\Crypto\KeyPaddingInterface;

class Ansix923KeyPadding implements KeyPaddingInterface
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

        return $append > 1
            ? $key . str_repeat(chr(0), $append - 1) . chr($append)
            : $key . chr($append);
    }
}
