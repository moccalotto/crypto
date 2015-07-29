<?php

namespace Moccalotto\Crypto\DataPadding;

use Moccalotto\Crypto\DataPaddingInterface;

class Pkcs7DataPadding implements DataPaddingInterface
{
    public function pad($data, $block_size)
    {
        $orig_length = strlen($data);
        $append = $block_size - $orig_length % $block_size;

        if ($block_size === $append) {
            return $data;
        }

        return $data . str_repeat(chr($append), $append);
    }

    public function unpad($data, $block_size)
    {
        $last_char = $data[strlen($data)-1];
        if (ord($last_char) >= $block_size) {
            return $data;
        }
        if (substr($data, -ord($last_char)) !== str_repeat($last_char, ord($last_char))) {
            return $data;
        }
        return substr($data, 0, -ord($last_char));
    }
}
