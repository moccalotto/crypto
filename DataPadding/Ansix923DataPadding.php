<?php

namespace Moccalotto\Crypto\DataPadding;

use Moccalotto\Crypto\DataPaddingInterface;

class Ansix923DataPadding implements DataPaddingInterface
{
    public function pad($data, $block_size)
    {
        $orig_length = strlen($data);
        $append = $block_size - $orig_length % $block_size;

        if ($block_size === $append) {
            return $data;
        }

        return $append > 1
            ? $data . str_repeat(chr(0), $append - 1) . chr($append)
            : $data . chr($append);
    }

    public function unpad($data, $block_size)
    {
        $last_char = $data[strlen($data)-1];
        if (ord($last_char) >= $block_size) {
            return $data;
        }
        if (substr($data, -ord($last_char)) !== str_repeat(chr(0), ord($last_char) - 1) . $last_char) {
            return $data;
        }
        return substr($data, 0, -ord($last_char));
    }
}
