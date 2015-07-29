<?php

namespace Moccalotto\Crypto\KeyPadding;

use Moccalotto\Crypto\KeyPaddingInterface;

class MysqlKeyPadding implements KeyPaddingInterface
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

        $final_key = str_repeat(chr(0), $key_size);
        foreach (str_split($key) as $index => $char) {
            $final_key[$index % $key_size] = $final_key[$index % $key_size] ^ $char;
        }
        return $final_key;
    }
}
