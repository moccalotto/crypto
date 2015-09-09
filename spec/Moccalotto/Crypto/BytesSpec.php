<?php

namespace spec\Moccalotto\Crypto;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class BytesSpec extends ObjectBehavior
{
    function it_counts_number_of_bytes_in_strings()
    {
        $this::count('foo')->shouldBe(3);
        $this::count(chr(1) . chr(2) . chr(3) . chr(253) . chr(254) . chr(255))->shouldBe(6);
        $this::count(' ಃಅಆ æøå ₠₡₢₣₤₥₦₧₨₩₪₫ ←↑→↓')->shouldBe(67);
    }

    function it_generates_random_bytes()
    {
        $this::random(1)->shouldHaveLength(1);
        $this::random(10)->shouldHaveLength(10);
        $this::random(100)->shouldHaveLength(100);
    }

    function it_slices_strings()
    {
        $this::slice('foobar', 0)->shouldBe('foobar');
        $this::slice('foobar', 3)->shouldBe('bar');
        $this::slice('foobar', 3, 2)->shouldBe('ba');
        $this::slice('foobar', -2)->shouldBe('ar');
        $this::slice('foobar', -4, 3)->shouldBe('oba');
    }

    public function getMatchers()
    {
        return [
            'haveLength' => function ($subject, $length) {
                if (!is_string($subject)) {
                    return false;
                }
                return mb_strlen($subject, '8bit') === $length;
            },
        ];
    }

}
