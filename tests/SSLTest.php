<?php
use PHPUnit\Framework\TestCase;

class SSLTest extends TestCase
{
    public function testGeneratePubicKey()
    {
        list($pbk, $pvk, $id) = \Secret\SSL::generate();

        file_put_contents(__DIR__ . '/tmp/autossl.pub', $pbk);
        file_put_contents(__DIR__ . '/tmp/autossl', $pvk);

        list($pbk, $pvk, $id) = \Secret\SSL::generate();

        $this->assertTrue(
            strpos($pbk, "PUBLIC") !== false
        );

        list($pbk, $pvk, $id) = \Secret\SSL::generate(
            file_get_contents(__DIR__ . '/tmp/autossl')
        );

        $this->assertTrue(
            strpos($pbk, "PUBLIC") !== false
        );
    }

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

        $this->assertTrue(isset($result));
    }
}
