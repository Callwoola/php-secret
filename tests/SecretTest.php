<?php
use PHPUnit\Framework\TestCase;

class SecretTest extends TestCase
{

    public $clientConfig = [
        'app_id' => 'mock id',
        'secret_key' => '',
        'self_ssl_file' => __DIR__ . '/tmp/client_ssl',
    ];

    public $serverConfig = [
        'self_ssl_file' => __DIR__ . '/tmp/server_ssl',
    ];

    public function award()
    {
        $server = new \Secret\Server($this->serverConfig);

        $result = $server->generate();

        return $result;
    }

    public function testUnit()
    {
        $sendData = json_encode(
            [
                'mock',
                'mock_test',
            ]
        );

        $award = $this->award();
        $this->clientConfig['secret_key'] = $award['PBK'];
        $this->clientConfig['app_id'] = $award['app_id'];

        $client = new \Secret\Client($this->clientConfig);
        $transfer = $client->encode($sendData);

        $result = $this->server($transfer);
        $result = $client->decode($result);

        $this->assertEquals($result, $sendData);
    }

    public function server($data)
    {
        $server = new \Secret\Server($this->serverConfig);
        $decode = $server->decode($data);

        return $server->revert($decode['data']);
    }
}
