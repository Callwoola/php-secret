<?php
namespace Secret;

class Client implements SecretInterface
{
    const RESPONSE_DELAY = 'delay';
    const RESPONSE_IMMEDIATELY = 'immediately';

    public $clientPBK = '';
    public $clientPVK = '';

    private $config = [];

    public function __construct($config = [])
    {
        $this->config = $config;
        $this->checkConfig();
        $this->checkAndGenerateKeyFile();
    }


    private function checkConfig()
    {
        if (!isset($this->config['self_ssl_file'])) throw new \RuntimeException('self_ssl_file of config was empty.');
        if (!isset($this->config['app_id'])) throw new \RuntimeException('app_id of config was empty.');
        if (!isset($this->config['secret_key'])) throw new \RuntimeException('secret_key of config was empty.');
    }

    private function checkandgeneratekeyfile()
    {
        if (isset($this->config['self_ssl_file']) && !is_file($this->config['self_ssl_file'])) {
            // auto generate key file...
            $path = pathinfo($this->config['self_ssl_file']);
            @mkdir($path['dirname'], true);
            if ($path['dirname']) {
                list($pbk, $pvk, $appid) = ssl::generate();
                file_put_contents($this->config['self_ssl_file'], $pvk);
                file_put_contents($this->config['self_ssl_file'] . '.pub', $pbk);
            }
        }

        if (!is_file($this->config['self_ssl_file'])) {
            throw new \runtimeexception('private key don\'t found.');
        }

        //ssl::$privatekey = file_get_contents($path['basename']);
        //ssl::$publickey = file_get_contents($path['basename'] . '.pub');

    }


    /**
     * {@inheritdoc}
     */
    public function encode($data = '', $type = self::RESPONSE_IMMEDIATELY)
    {
        if (!is_string($data)) {
            throw new \RuntimeException('Data must be a string.');
        }

        // use secret encode of server for push to server
        SSL::$publicKey = SSL::attireIn($this->config['secret_key']);
        $type = function () use ($type) {
            if (in_array($type, [self::RESPONSE_IMMEDIATELY, self::RESPONSE_DELAY])) {
                return $type;
            }
            throw new \RuntimeException('Response type was error.');
        };

        $data = [
            'data' => $data,
            'client_public_key' => file_get_contents($this->config['self_ssl_file'] . '.pub'),
            'app_id' => $this->config['app_id'],
            'type' => $type(),
        ];

        $data = SSL::encode(
            json_encode($data)
        );

        SSL::destroy();

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    public function decode($data = '')
    {
        if (!is_string($data)) {
            throw new \RuntimeException('Data must be a string.');
        }

        SSL::$privateKey = file_get_contents($this->config['self_ssl_file']);

        $data = SSL::decode($data);
        SSL::destroy();

        return $data;
    }
}