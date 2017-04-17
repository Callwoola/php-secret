<?php
namespace Secret;

class Server
{
    private $config = [];
    private $response = null;

    // Transfer package for target
    public function __construct($config = [])
    {
        $this->config = $config;
        $this->checkConfig();
        $this->checkAndGenerateKeyFile();
    }

    private function checkConfig()
    {
        // server ssl file. It just only one.
        if (!isset($this->config['self_ssl_file'])) throw new \RuntimeException('self_ssl_file of config was empty.');
    }

    private function checkAndGenerateKeyFile()
    {
        if (isset($this->config['self_ssl_file']) && !is_file($this->config['self_ssl_file'])) {
            // auto generate key file...
            $path = pathinfo($this->config['self_ssl_file']);
            @mkdir($path['dirname'], true);
            if ($path['dirname']) {
                list($pbk, $pvk, $appid) = ssl::generate();
                file_put_contents($this->config['self_ssl_file'], $pvk);
            }
        }

        if (!is_file($this->config['self_ssl_file'])) {
            throw new \runtimeexception('private key don\'t found.');
        }
    }

    public $data;
    public $clientPublicKey;
    public $appId;
    public $type;

    private function response($decode)
    {
        try {
            $this->data = $decode['data'];
            $this->clientPublicKey = $decode['client_public_key'];
            $this->appId = $decode['app_id'];
            $this->type = $decode['type'];
            if (!in_array($this->type, [Client::RESPONSE_IMMEDIATELY, Client::RESPONSE_DELAY,])) {
                throw new \RuntimeException('Type incorrect.');
            }
        } catch (\Exception $e) {
            throw new \RuntimeException('Decode error: ' . $e->getMessage());
        }

        return [
            'data' => $this->data,
            'client_public_key' => $this->clientPublicKey,
            'app_id' => $this->appId,
            'type' => $this->type,
        ];
    }

    public function revert($data)
    {
        SSL::$publicKey = $this->clientPublicKey;
        $result = SSL::encode($data);
        SSL::destroy();

        return $result;
    }

    public function decode($data = '')
    {
        SSL::$privateKey = file_get_contents($this->config['self_ssl_file']);
        $result = $this->response(
            json_decode(SSL::decode($data), true)
        );
        SSL::destroy();

        return $result;
    }

    public function generate()
    {
        SSL::$privateKey = file_get_contents($this->config['self_ssl_file']);
        list($PBK, $PVK, $app_id) = SSL::generate(SSL::$privateKey);
        $PBK = SSL::stripOff($PBK);

        return compact('PBK', 'app_id');
    }
}