# crypto

Encrypt data using aes-128-cbc. Message authentication is done via sha-256 HMAC

```php
<?php

use Moccalotto\Crypto\Crypto;

require 'vendor/autoload.php';

$key = 'some secret key';

$plaintext = 'This is the secret plaintext to be encrypted';

$encrypted = Crypto::with($key)->encrypt($plaintext);

echo Crypto::with($key)->decrypt($encrypted);
```
