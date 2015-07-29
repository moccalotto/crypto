<?php

namespace Moccalotto\Crypto;

class Cipher
{
    protected $name;
    protected $bits;
    protected $descriptor;
    protected $blockMode;
    protected $dataPadding;
    protected $keyPadding;

    public function __construct($descriptor, $blockMode, DataPaddingInterface $dataPadding, KeyPaddingInterface $keyPadding)
    {
        if (!in_array($descriptor, mcrypt_list_algorithms())) {
            throw new \RuntimeException(sprintf(
                'Algorithm descriptor »%s« does not work. Use one of these: [%s]',
                $descriptor,
                implode(',', mcrypt_list_algorithms())
            ));
        }
        if (!in_array($blockMode, mcrypt_list_modes())) {
            throw new \RuntimeException(sprintf(
                'Block mode »%s« does not work. Use one of these: [%s]',
                $blockMode,
                implode(',', mcrypt_list_modes())
            ));
        }
        $descriptor_parts = explode('-', $descriptor);
        $this->name = $name = $descriptor_parts[0];
        $this->bits = isset($descriptor_parts[1]) ? $descriptor_parts[1] : null;
        $this->descriptor = $descriptor;
        $this->blockMode = $blockMode;
        $this->dataPadding = $dataPadding;
        $this->keyPadding = $keyPadding;
    }

    public function getDescriptor()
    {
        return $this->descriptor;
    }

    public function getBits()
    {
        return $this->bits;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getBlockMode()
    {
        return $this->blockMode;
    }

    public function getBlockSize()
    {
        return mcrypt_get_block_size($this->descriptor, $this->blockMode);
    }

    public function getIvSize()
    {
        if (MCRYPT_MODE_ECB === $this->blockMode) {
            return 0;
        }
        return mcrypt_get_iv_size($this->descriptor, $this->blockMode);
    }

    public function getKeySize()
    {
        return mcrypt_get_key_size($this->descriptor, $this->blockMode);
    }

    public function getRandomIv()
    {
        return mcrypt_create_iv($this->getIvSize());
    }

    public function padData($plaintext)
    {
        return $this->dataPadding->pad($plaintext, $this->getBlockSize());
    }

    public function unpadData($plaintext)
    {
        return $this->dataPadding->unpad($plaintext, $this->getBlockSize());
    }

    public function padKey($key)
    {
        return $this->keyPadding->pad($key, $this->getKeySize());
    }
}
