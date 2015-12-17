<?php

namespace Moccalotto\Crypto;

class Crypto
{
    const PURPOSE_ENCRYPTION = 'encryption';
    const PURPOSE_AUTHENTICATION = 'authentication';

    /*
     * The base key used to derive authentication and encryption keys.
     *
     * @var string
     */
    protected $key;

    /*
     * The name of the hash algorithm used for authentication
     *
     * @var string
     */
    protected $hash = 'sha256';

    /*
     * The number of bytes in the raw hash digest
     *
     * @var int
     */
    protected $hashBytes = 32;

    /*
     * The identifier of the encryption algorithm
     *
     * @var string
     */
    protected $cipher = 'aes-128-cbc';

    /*
     * The number of bytes in the encryption key
     *
     * @var int
     */
    protected $keyBytes = 32;

    /*
     * The number of bytes in the initialization vector
     *
     * @var int
     */
    protected $ivBytes = 16;

    /**
     * Ensure that salt has the correct number of bytes.
     *
     * Technically, this call is not necessary, as we hardcode the salt,
     * but the encryption RFC specify it. We keep it here to be compatible
     * with future changes to the salt.
     *
     * @link https://tools.ietf.org/html/rfc5869
     *
     * @param string|null $salt
     *
     * @return string
     */
    protected function ensureCorrectSalt($salt)
    {
        if (null === $salt) {
            return str_repeat(chr(0), $this->hashBytes);
        }

        return $salt;
    }

    /**
     * Get a derived key.
     *
     * @link https://tools.ietf.org/html/rfc5869
     *
     * @param string $purpose
     * @param string $salt
     *
     * @return string
     */
    public function getDerivedKey($purpose, $salt)
    {
        // see: https://tools.ietf.org/html/rfc5869
        // step 1: extract a pseudorandom base key
        $base_key = hash_hmac(
            $this->hash,
            $this->key,
            $this->ensureCorrectSalt($salt),
            true
        );

        // step 2: expand/derive an output key
        $key_so_far = '';
        $latest_key_block = '';
        for ($i = 1; Bytes::count($key_so_far) < $this->keyBytes; ++$i) {
            $latest_key_block = hash_hmac(
                $this->hash,
                $latest_key_block.$purpose.\chr($i),
                $base_key,
                true
            );
            $key_so_far .= $latest_key_block;
        }

        return Bytes::slice($key_so_far, 0, $this->keyBytes);
    }

    /**
     * Get the encryption key.
     *
     * The key is derived from $this->key
     *
     * @return string
     */
    public function getDerivedEncryptionKey()
    {
        return $this->getDerivedKey(
            static::PURPOSE_ENCRYPTION,
            static::PURPOSE_ENCRYPTION
        );
    }

    /**
     * Get the authentication key.
     *
     * The key is derived from $this->key
     *
     * @return string
     */
    public function getDerivedAuthenticationKey()
    {
        return $this->getDerivedKey(
            static::PURPOSE_AUTHENTICATION,
            static::PURPOSE_AUTHENTICATION
        );
    }

    /**
     * Constructor
     *
     * @param string $key
     */
    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * Create an object with the given key
     *
     * @param string $key
     *
     * @return Crypto
     */
    public static function with($key)
    {
        return new static($key);
    }

    /**
     * Change cipher.
     *
     * For advanced or specialized use cases only.
     * We only self-test the standard algorithms - deviate from the
     * standards at your own risk.
     *
     * @param string $cipher   The openssl cipher to use.
     * @param int    $keyBytes The size of the key in bytes.
     * @param int    $ivBytes  The size of the initialization vector in bytes.
     *
     * @return $this
     */
    public function withCipher($cipher, $keyBytes, $ivBytes)
    {
        $this->cipher = $cipher;
        $this->keyBytes = $keyBytes;
        $this->ivBytes = $ivBytes;

        return $this;
    }

    /**
     * Change hash algorithm.
     *
     * For advanced or specialized use cases only.
     * We only self-test the standard algorithms - deviate from the
     * standards at your own risk.
     *
     * @param string $hash      The hash algoruth to use.
     * @param int    $hashBytes The size of the outputted raw digest.
     *
     * @return $this
     */
    public function withHash($hash, $hashBytes)
    {
        $this->hash = $hash;
        $this->hashBytes = $hashBytes;

        return $this;
    }

    /**
     * Encrypt a string
     *
     * @param string $string
     *
     * @return EncryptedData
     */
    public function encrypt($string)
    {
        $iv = Bytes::random($this->ivBytes);

        $ciphertext = openssl_encrypt(
            $string,
            $this->cipher,
            $this->getDerivedEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv
        );

        $auth = hash_hmac(
            $this->hash,
            $iv.$ciphertext,
            $this->getDerivedAuthenticationKey(),
            true
        );

        return new EncryptedData(
            $auth,
            $iv,
            $ciphertext,
            $this->hash,
            $this->hashBytes,
            $this->cipher,
            $this->keyBytes,
            $this->ivBytes
        );
    }

    /**
     * Decrypt ciphertext into plaintext.
     *
     * @param EncryptedData|string $ciphertext The data to be decrypted.
     *
     * @return string the decrypted plaintext
     *
     * @throws MessageTamperingException if the message has been tampered with.
     */
    public function decrypt($ciphertext)
    {
        $data = $ciphertext instanceof EncryptedData ? $ciphertext : EncryptedData::fromText($ciphertext);

        if (!($data->getHash() === $this->hash && $data->getCipher() === $this->cipher)) {
            return static::with($this->key)
                ->withHash($data->getHash(), $data->getHashBytes())
                ->withCipher($data->getCipher(), $data->getKeyBytes(), $data->getIvBytes())
                ->decrypt($ciphertext);
        }

        $auth_should_be = hash_hmac(
            $this->hash,
            $data->getIv().$data->getCiphertext(),
            $this->getDerivedAuthenticationKey(),
            true
        );

        if ($auth_should_be !== $data->getAuth()) {
            throw new MessageTamperingException('Could not decrypt this message. It has been tampered with or forged.');
        }

        $plaintext = openssl_decrypt(
            $data->getCiphertext(),
            $this->cipher,
            $this->getDerivedEncryptionKey(),
            OPENSSL_RAW_DATA,
            $data->getIv()
        );

        if (false === $plaintext) {
            throw new RuntimeException('Could not decrypt this message. openssl_decrypt failed');
        }

        return $plaintext;
    }
}
