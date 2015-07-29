<?php

namespace Moccalotto\Crypto\DataPadding;

use Moccalotto\Crypto\DataPaddingInterface;

class ZerosDataPadding implements DataPaddingInterface
{
    public function pad($data, $block_size)
    {
        $orig_length = strlen($data);
        $append = $block_size - $orig_length % $block_size;

        if ($block_size === $append) {
            return $data;
        }

        return $data . str_repeat(chr(0), $append);
    }

    public function unpad($data, $block_size)
    {
        return rtrim($data, chr(0));
    }
}
