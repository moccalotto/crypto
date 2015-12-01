# Crypto

Encrypt data using aes-128-cbc. Message authentication is done via sha-256 HMAC

## Installation

To add this package as a local, per-project dependency to your project, simply add a dependency on
 `moccalotto/crypto` to your project's `composer.json` file like so:

```json
{
    "require": {
        "moccalotto/crypto": "~0.8"
    }
}
```

Alternatively simply call `composer require moccalotto/crypto`


## Demo

```php
<?php

use Moccalotto\Crypto\Crypto;

require 'vendor/autoload.php';

$key = 'some secret key';

$plaintext = 'This is the secret plaintext to be encrypted';

$encrypted = Crypto::with($key)->encrypt($plaintext);

echo Crypto::with($key)->decrypt($encrypted);
```
