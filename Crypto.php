<?php

namespace Moccalotto\Crypto;

class Crypto
{
    protected $cipher;
    protected $key;
    protected $iv;

    public function __construct(Cipher $cipher, $key, $iv = null)
    {
        $this->cipher = $cipher;
        $this->key = $key;
        if (null === $iv) {
            $this->iv = $cipher->getRandomIv();
            return;
        }
        if (strlen($iv) === $cipher->getIvSize()) {
            $this->iv = $iv;
            return;
        }

        throw new \LengthException(sprintf(
            'Unexpectev IV length. Given IV is %d bytes long, but should be %d bytes long.',
            strlen($iv),
            $cipher->getIvSize()
        ));
    }

    public function encrypt($plaintext)
    {
        return mcrypt_encrypt(
            $this->cipher->getDescriptor(),
            $this->cipher->padKey($this->key),
            $this->cipher->padData($plaintext),
            $this->cipher->getBlockMode(),
            $this->iv
        );
    }

    public function decrypt($ciphertext)
    {
        return $this->cipher->unpadData(mcrypt_decrypt(
            $this->cipher->getDescriptor(),
            $this->cipher->padKey($this->key),
            $ciphertext,
            $this->cipher->getBlockMode(),
            $this->iv
        ));
    }

    public function getKey()
    {
        return $this->key;
    }

    public function getIv()
    {
        return $this->iv;
    }
}
