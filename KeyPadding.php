<?php

namespace Moccalotto\Crypto;

class KeyPadding
{
    const MODE_ANSIX923 = 'ANSIX923';
    const MODE_PKCS7    = 'PKCS7';
    const MODE_ZEROS    = 'ZEROS';
    const MODE_MYSQL    = 'MYSQL';

    const ALL_MODES = [
        self::MODE_ANSIX923,
        self::MODE_PKCS7,
        self::MODE_ZEROS,
        self::MODE_MYSQL,
    ];

    protected $mode;

    public function __construct($mode)
    {
        if (!in_array($mode, self::ALL_MODES)) {
            throw new \UnexpectedValueException(sprintf(
                'Padding mode »%s« is not valid. Use one of [%s].',
                $mode,
                implode(',', self::ALL_MODES)
            ));
        }
        $this->mode = $mode;
    }

    public static function getModes()
    {
        return self::ALL_MODES;
    }

    public function pad($key, $key_size)
    {
        $orig_length = strlen($key);
        $append = $key_size - $orig_length;

        if (0 === $append) {
            return $key;
        }

        if ($append < 0) {
            return substr($key, $key_size);
        }

        switch ($this->mode) {
        case self::MODE_ANSIX923:
            return $append > 1
                ? $key . str_repeat(chr(0), $append - 1) . chr($append)
                : $key . chr($append);
        case self::MODE_PKCS7:
            return $key . str_repeat(chr($append), $append);
        case self::MODE_ZEROS:
            return $key . str_repeat(chr(0), $append);
        case self::MODE_MYSQL:
            $final_key = str_repeat(chr(0), $key_size);
            foreach (str_split($key) as $index => $char) {
                $final_key[$index % $key_size] = $final_key[$index % $key_size] ^ $char;
            }
            return $final_key;
        default:
            throw new \LogicException('This code should not be reachable');
        }
    }
}
