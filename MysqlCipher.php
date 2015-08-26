<?php

namespace Moccalotto\Crypto;

use Moccalotto\Crypto\DataPadding\Pkcs7DataPadding;
use Moccalotto\Crypto\KeyPadding\MysqlKeyPadding;

class MysqlCipher extends Cipher
{
    protected $actualKeySize;

    const MYSQL_DEFAULT = 'aes-128-ecb';

    public function __construct($block_encryption_mode = self::MYSQL_DEFAULT)
    {
        // AES is rijndael with a block size of 128.
        // rijndael itself can have block sizes of 128, 192 and 256.
        // It can also support key sizes of 128, 192 and 256, independantly of the block size.
        // AES has a fixed block size, but support key sizes of 128, 192 or 256 bits.
        // Therefore we use MCRYPT_RIJNDAEL_128, but vary the key sizes.

        // parse the $block_encryption_mode to see which key size is to be used.
        if (!preg_match('/([a-z]+)-([0-9]+)-([a-z]+)$/A', $block_encryption_mode, $matches)) {
            throw new \UnexpectedValueException('Bad syntax of $block_encryption_mode. Refer to the block_encryption_mode variable documentation of mariadb/mysql');
        }

        list($_, $algorithm, $this->actualKeySize, $block_mode) = $matches;

        if ($algorithm !== 'aes') {
            throw new \UnexpectedValueException('Only AES compatibility is supported by this library');
        }
        parent::__construct(MCRYPT_RIJNDAEL_128, $block_mode, new Pkcs7DataPadding(), new MysqlKeyPadding());
    }

    public function getKeySize()
    {
        return $this->actualKeySize / 8;
    }
}
