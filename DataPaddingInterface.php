<?php

namespace Moccalotto\Crypto;

interface DataPaddingInterface
{
    public function pad($data, $block_size);
    public function unpad($data, $block_size);
}
