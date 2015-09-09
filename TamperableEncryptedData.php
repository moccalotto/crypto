<?php

namespace Moccalotto\Crypto;

class TamperableEncryptedData extends EncryptedData
{
    public function changeChar($char)
    {
        return chr(ord($char) + 2 % 255);
    }

    public function tamperIv()
    {
        $this->iv[0] = $this->changeChar($this->iv[0]);
    }

    public function tamperCipherText()
    {
        $this->ciphertext[0] = $this->changeChar($this->ciphertext[0]);
    }

    public function tamperAuth()
    {
        $this->auth[0] = $this->changeChar($this->auth[0]);
    }

    public static function fromBase(EncryptedData $other)
    {
        return static::fromArray($other->toArray());
    }
}
