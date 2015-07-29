# crypto
A small mcrypt wrapper for encryption

```php
<?php

require 'vendor/autoload.php';

use Moccalotto\Crypto\Cipher;
use Moccalotto\Crypto\Manager;
use Moccalotto\Crypto\DataPadding\Pkcs7DataPadding;
use Moccalotto\Crypto\KeyPadding\Pkcs7KeyPadding;

$cipher = new Cipher(
    MCRYPT_RIJNDAEL_256,
    MCRYPT_MODE_CBC,
    new Pkcs7DataPadding(),
    new Pkcs7KeyPadding()
);


$passphrase = 'my fancy and very long passphrase';

$initialization_vector = openssl_random_pseudo_bytes($cipher->getIvSize()); 
// we could do this:
// $initialization_vector = $cipher->getRandomIv()

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
```
