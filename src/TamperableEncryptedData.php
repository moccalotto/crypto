<?php

namespace Moccalotto\Crypto;

/**
 * Version of EncryptedData that allows tampering.
 *
 * Used during unit testing
 */
class TamperableEncryptedData extends EncryptedData
{
    /**
     * Change a character to something else.
     *
     * Basically rotate it a step to the left.
     *
     * @param string $char One single character
     *
     * @return string
     */
    public function changeChar($char)
    {
        return chr(ord($char) + 2 % 255);
    }

    /**
     * Change the first byte of the initialization vector.
     */
    public function tamperIv()
    {
        $this->iv[0] = $this->changeChar($this->iv[0]);
    }

    /**
     * Change the first byte of the ciphertext.
     */
    public function tamperCipherText()
    {
        $this->ciphertext[0] = $this->changeChar($this->ciphertext[0]);
    }

    /**
     * Change the first byte of the authication signature
     */
    public function tamperAuth()
    {
        $this->auth[0] = $this->changeChar($this->auth[0]);
    }

    /**
     * Create an instance of TamperableEncryptedData from an EncryptedData instance.
     *
     * @param EncryptedData $other
     *
     * @return TamperableEncryptedData
     */
    public static function fromBase(EncryptedData $other)
    {
        return static::fromArray($other->toArray());
    }
}
