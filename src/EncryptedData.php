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

    /**
     * Constructor.
     *
     * @param string $auth
     * @param string $iv
     * @param string $ciphertext
     * @param string $hash
     * @param int $hashBytes
     * @param string $cipher
     * @param int $keyBytes
     * @param int $ivBytes
     */
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

    /**
     * Create an instance from an array of data.
     *
     * @param array $array
     *
     * @return EncryptedData
     */
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
            $ciphertext) = $array;

        return new static($auth, $iv, $ciphertext, $hash, $hashBytes, $cipher, $keyBytes, $ivBytes);
    }

    /**
     * Create a real instance from a base64-serialized instance.
     *
     * @param string $string
     *
     * @return EncryptedData
     */
    public static function fromText($string)
    {
        return static::fromArray(unserialize(base64_decode($string)));
    }

    /**
     * Convert this instance to an array, containing all state data
     *
     * @return array
     */
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

    /**
     * Serialize this instance into a base64 coded string
     *
     * @return string
     */
    public function toText()
    {
        return base64_encode(serialize($this->toArray()));
    }

    /**
     * Alias of $this->toText()
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toText();
    }

    /**
     * Get the cipher used to encrypt the data.
     *
     * @return string
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * Get the number of bytes in the key.
     *
     * @return string
     */
    public function getKeyBytes()
    {
        return $this->keyBytes;
    }

    /**
     * Get the the number of bytes in the initialization vector.
     *
     * @return int
     */
    public function getIvBytes()
    {
        return $this->ivBytes;
    }

    /**
     * Get the hash algorithm used to auth/sign the encrypted data.
     *
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Get the number of bytes in the authentication signature.
     *
     * @return int
     */
    public function getHashBytes()
    {
        return $this->hashBytes;
    }

    /**
     * Get the authentication signature.
     *
     * @return string
     */
    public function getAuth()
    {
        return $this->auth;
    }

    /**
     * Get the initialization vector
     *
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * Get the encrypted ciphertext.
     *
     * @return string
     */
    public function getCiphertext()
    {
        return $this->ciphertext;
    }
}
