<?php

namespace Moccalotto\Crypto;

interface KeyPaddingInterface
{
    public function pad($key, $key_size);
}
