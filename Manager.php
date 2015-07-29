<?php

namespace Moccalotto\Crypto;

class Manager
{
    protected $cipher;

    public function __construct(Cipher $cipher)
    {
        $this->cipher = $cipher;
    }

    public function getCipher()
    {
        return $cipher;
    }

    public function getCrypto($key, $iv = null)
    {
            return new Crypto(
                $this->cipher,
                $key,
                $iv
            );
    }

    public function encrypt($plaintext, $key, $iv = null)
    {
        $crypto = $this->getCrypto($key, $iv);
        $iv = $crypto->getIv();
        return $this->getCrypto($key, $iv)->encrypt($plaintext);
    }

    public function decrypt($ciphertext, $key, $iv = null)
    {
        $crypto = $this->getCrypto($key, $iv);
        $iv = $crypto->getIv();
        return $this->getCrypto($key, $iv)->decrypt($ciphertext);
    }
}
