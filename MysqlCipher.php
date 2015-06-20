<?php

namespace Moccalotto\Crypto;

class MysqlCipher extends Cipher
{
    protected $actualKeySize;

    public function __construct($block_encryption_mode)
    {
        // AES is always rijndael with a block size of 128.
        // rijndael can have block sizes of 128, 192 and 256.
        // It can also support key sizes of 128, 192 and 256, independantly of the block size.
        // AES has a fixed block size,but support key sizes of 128, 192 or 256 bits.


        // parse the $block_encryption_mode to see which key size is to be used.
        if (!preg_match('/\[a-z]+-[0-9]+-[a-z]+$/A', $block_encryption_mode)) {
            throw new \UnexpectedValueException('Bad syntax of $block_encryption_mode. Refer to the block_encryption_mode variable documentation of mariadb/mysql');
        }
        list($algorithm, $this->actualKeySize, $block_mode) = explode('-', $block_encryption_mode);
        if ($algorithm !== 'aes') {
            throw new \UnexpectedValueException('Only AES compatibility is supported by this library');
        }
        parent::__construct(MCRYPT_RIJNDAEL_128, $block_mode, new DataPadding(DataPadding::MODE_PKCS7) new KeyPadding(KeyPadding::MODE_MYSQL));
    }

    public function getKeySize()
    {
        return $this->actualKeySize();
    }
}
