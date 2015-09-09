<?php

namespace Moccalotto\Crypto;

use UnexpectedValueException;

class EncryptedData
{
    protected $auth;
    protected $iv;
    protected $ciphertext;
    
    // hash algorithm
    protected $hash;
    protected $hashBytes;

    // cipher algorithm
    protected $cipher;
    protected $keyBytes;
    protected $ivBytes;

    public function __construct($auth, $iv, $ciphertext, $hash, $hashBytes, $cipher, $keyBytes, $ivBytes)
    {
        $this->auth = $auth;
        $this->iv = $iv;
        $this->ciphertext = $ciphertext;

        $this->hash = $hash;
        $this->hashBytes = $hashBytes;

        $this->cipher = $cipher;
        $this->keyBytes = $keyBytes;
        $this->ivBytes = $ivBytes;
    }

    public static function fromArray(array $array)
    {
        if (count($array) !== 8) {
            throw new UnexpectedValueException(sprintf(
                'You must pass an array with 8 entries. You passed an array with %d entries',
                count($array)
            ));
        }

        list(
            $cipher,
            $keyBytes,
            $ivBytes,
            $hash,
            $hashBytes,
            $auth,
            $iv,
            $ciphertext,
        ) = $array;

        return new static($auth, $iv, $ciphertext, $hash, $hashBytes, $cipher, $keyBytes, $ivBytes);
    }

    public static function fromText($string)
    {
        return static::fromArray(unserialize(base64_decode($string)));
    }

    public function toArray()
    {
        return [
            $this->cipher,
            $this->keyBytes,
            $this->ivBytes,
            $this->hash,
            $this->hashBytes,
            $this->auth,
            $this->iv,
            $this->ciphertext,
        ];
    }

    public function toString()
    {
        return base64_encode(serialize($this->toArray()));
    }

    public function __toString()
    {
        return $this->toString();
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKeyBytes()
    {
        return $this->keyBytes;
    }

    public function getIvBytes()
    {
        return $this->ivBytes;
    }

    public function getHash()
    {
        return $this->hash;
    }

    public function getHashBytes()
    {
        return $this->hashBytes;
    }

    public function getAuth()
    {
        return $this->auth;
    }

    public function getIv()
    {
        return $this->iv;
    }

    public function getCiphertext()
    {
        return $this->ciphertext;
    }
}
