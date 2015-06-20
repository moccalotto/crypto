# crypto
A small mcrypt wrapper for encryption

```php
<?php

// do some standard crypto

use Moccalotto\Crypto\Cipher;
use Moccalotto\Crypto\Manager;
use Moccalotto\Crypto\DataPadding;
use Moccalotto\Crypto\KeyPadding;
use Moccalotto\Crypto\MysqlCipher;

$cipher = new Cipher(
    MCRYPT_RIJNDAEL_256,
    MCRYPT_MODE_CBC,
    new DataPadding(DataPadding::MODE_PKCS7),
    new KeyPadding(KeyPadding::MODE_PKCS7)
);

$initialization_vector = 'this is just some text we make up. The text may be changed when I call encrypt()';
$passphrase = 'my fancy and very long passphrase';

$manager = new Manager($cipher);
$ciphertext = $manager->encrypt(
    'this is some plain text',
    $passphrase,
    $initialization_vector
);

echo $manager->decrypt(
    $ciphertext,
    $passphrase,
    $initialization_vector
);
// this is some plain text
```
