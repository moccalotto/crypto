<?php

namespace spec\Moccalotto\Crypto;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Moccalotto\Crypto\TamperableEncryptedData;

class CryptoSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $key = 'some key';
        $this->beConstructedWith($key);
        $this->shouldHaveType('Moccalotto\Crypto\Crypto');
    }

    function it_encrypts_a_string()
    {
        $key = 'some key';
        $plaintext = 'my text';
        $this->beConstructedWith($key);
        $this->encrypt($plaintext)->shouldHaveType('Moccalotto\Crypto\EncryptedData');
    }

    function it_decrypts_an_EncryptedData_object()
    {
        $key = 'some key';
        $plaintext = 'my text';
        $this->beConstructedWith($key);

        $actual = $this->getWrappedObject();
        $encrypted = $actual->encrypt($plaintext);
        $this->decrypt($encrypted)->shouldBe($plaintext);
    }

    function it_descrypts_a_string()
    {
        $key = 'some key';
        $plaintext = 'my text';
        $this->beConstructedWith($key);

        $actual = $this->getWrappedObject();
        $encrypted = $actual->encrypt($plaintext);
        $this->decrypt($encrypted->toText())->shouldBe($plaintext);
    }

    function it_detects_tampering()
    {
        $key = 'some key of doom and destruction';
        $this->beConstructedWith($key);

        for ($i = 0; $i < 10; $i++) {
            $plaintext = "some $i long $i text of $i doom";

            $actual = $this->getWrappedObject();
            $encrypted = TamperableEncryptedData::fromBase($actual->encrypt($plaintext));
            $this->decrypt($encrypted)->shouldBe($plaintext);
            $encrypted->tamperIv();
            $this->shouldThrow('\Moccalotto\Crypto\MessageTamperingException')->duringDecrypt($encrypted);

            $encrypted = TamperableEncryptedData::fromBase($actual->encrypt($plaintext));
            $this->decrypt($encrypted)->shouldBe($plaintext);
            $encrypted->tamperCipherText();
            $this->shouldThrow('\Moccalotto\Crypto\MessageTamperingException')->duringDecrypt($encrypted);

            $encrypted = TamperableEncryptedData::fromBase($actual->encrypt($plaintext));
            $this->decrypt($encrypted)->shouldBe($plaintext);
            $encrypted->tamperAuth();
            $this->shouldThrow('\Moccalotto\Crypto\MessageTamperingException')->duringDecrypt($encrypted);
        }

    }
}
