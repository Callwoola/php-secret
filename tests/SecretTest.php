<?php
use PHPUnit\Framework\TestCase;

class SecretTest extends TestCase
{
    public function testBase()
    {
        $this->assertEmpty([]);
    }

    //public function testGetKey()
    //{
    //    $s = new \Secret\Server();
    //    $secretKey = $s->generate();
    //
    //    $this->assertTrue(true);
    //}

    public function testEncodeAndDecode()
    {
        $s = new \Secret\SSL();

        $encodingString = $s->encode(
            json_encode(
                [
                    'mock',
                    'mock',
                ]
            )
        );

        $result = $s->decode($encodingString);
        var_dump(
            json_decode($result)
        );

        $this->assertTrue(true);
    }
}
