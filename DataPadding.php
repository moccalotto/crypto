<?php

namespace Moccalotto\Crypto;

class DataPadding
{
    const MODE_ANSIX923 = 'ANSIX923';
    const MODE_PKCS7    = 'PKCS7';
    const MODE_ZEROS    = 'ZEROS';

    const ALL_MODES = [
        self::MODE_ANSIX923,
        self::MODE_PKCS7,
        self::MODE_ZEROS,
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

    public function pad($plaintext, $block_size)
    {
        $orig_length = strlen($plaintext);
        $append = $block_size - $orig_length % $block_size;

        if ($block_size === $append) {
            return $plaintext;
        }

        switch ($this->mode) {
        case self::MODE_ANSIX923:
            return $append > 1
                ? $plaintext . str_repeat(chr(0), $append - 1) . chr($append)
                : $plaintext . chr($append);
        case self::MODE_PKCS7:
            return $plaintext . str_repeat(chr($append), $append);
        case self::MODE_ZEROS:
            return $plaintext . str_repeat(chr(0), $append);
        default:
            throw new \LogicException('This code should not be reached');
        }
    }

    public function unpad($plaintext, $block_size)
    {
        switch ($this->mode) {
        case self::MODE_ANSIX923:
            $last_char = $plaintext[strlen($plaintext)-1];
            if (ord($last_char) >= $block_size) {
                return $plaintext;
            }
            if (substr($plaintext, -ord($last_char)) !== str_repeat(chr(0), ord($last_char) - 1) . $last_char) {
                return $plaintext;
            }
            return substr($plaintext, 0, -ord($last_char));

        case self::MODE_PKCS7:
            $last_char = $plaintext[strlen($plaintext)-1];
            if (ord($last_char) >= $block_size) {
                return $plaintext;
            }
            if (substr($plaintext, -ord($last_char)) !== str_repeat($last_char, ord($last_char))) {
                return $plaintext;
            }
            return substr($plaintext, 0, -ord($last_char));

        case self::MODE_ZEROS:
            return rtrim($plaintext, chr(0));

        default:
            throw new \LogicException('This code should not be reached');
        }
    }
}
