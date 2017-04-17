<?php
namespace Secret;

class SSL
{
    public static $publicKey = '';

    public static $privateKey = '';

    public static $sslConfig = [
        'digest_alg' => 'sha256',
        'private_key_bits' => 1024,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    public static function decode($encrypted)
    {
        if (!strlen(self::$privateKey) > 0) {
            throw new \RuntimeException('Private was empty.');
        }

        // decode
        $keyStr = self::$privateKey;

        if (!$privateKey = openssl_pkey_get_private($keyStr)) {
            throw new \RuntimeException('get private key failed' . "\n");
        }

        // echo 'encrypted data: ' . $encrypted;

        $encrypted = base64_decode($encrypted);

        $p_key = openssl_pkey_get_details($privateKey);
        $chunkSize = ceil($p_key['bits'] / 8);
        $output = '';

        while ($encrypted) {
            $chunk = substr($encrypted, 0, $chunkSize);
            $encrypted = substr($encrypted, $chunkSize);
            $decrypt = '';
            if (!openssl_private_decrypt($chunk, $decrypt, $privateKey)) {
                throw new \RuntimeException('failed to decrypt data' . "\n");
            }
            $output .= $decrypt;
        }

        openssl_free_key($privateKey);
        $output = gzuncompress($output);

        return $output;
    }

    public static function encode($data = [])
    {
        if (!strlen(self::$publicKey) > 0) {
            throw new \RuntimeException('Public was empty.');
        }

        $plain = gzcompress($data); // compress data
        $publicString = self::$publicKey;

        $publicKey = openssl_pkey_get_public($publicString);

        $extractKey = openssl_pkey_get_details($publicKey);
        $chunkSize = ceil($extractKey['bits'] / 8) - 11;

        $output = '';

        while ($plain) {
            $chunk = substr($plain, 0, $chunkSize);
            $plain = substr($plain, $chunkSize);

            $encrypted = '';
            if (!openssl_public_encrypt($chunk, $encrypted, $publicKey)) {
                throw new \RuntimeException("failed to encrypt data");
            }

            $output .= $encrypted;
        }

        openssl_free_key($publicKey);
        $output = base64_encode($output);

        return $output;
    }


    public static function stripOff($string = '', $isPub = true)
    {
        $title = $isPub ? 'PUBLIC' : 'PRIVATE';
        $string = @str_replace('-----BEGIN ' . $title . ' KEY-----', '', $string);
        $string = @str_replace('-----END ' . $title . ' KEY-----', '', $string);
        $string = @preg_replace("/\r|\n/", '', $string);

        return $string;
    }

    public static function attireIn($string, $isPub = true)
    {
        $title = $isPub ? 'PUBLIC' : 'PRIVATE';
        $string = chunk_split($string, 64);
        $string = '-----BEGIN ' . $title . ' KEY-----' . PHP_EOL . $string . '-----END ' . $title . ' KEY-----';

        return $string;
    }

    public static function generate($PVK = null)
    {
        $privateKey = null;

        if (!isset($PVK)) {
            $privateKey = openssl_pkey_new();
        } else {
            $privateKey = openssl_pkey_get_private($PVK);
        }

        if (!is_resource($privateKey)) throw new \RuntimeException('Private not a resource.');

        $key = openssl_pkey_get_details($privateKey);
        openssl_pkey_export($privateKey, $privateKeyString);
        self::$privateKey = $privateKeyString;
        $public = $key['key'];
        openssl_free_key($privateKey); // resolve key
        self::$publicKey = $public;

        return [
            self::$publicKey,
            self::$privateKey,
            self::generateAppId(),
        ];
    }

    public static function generateAppId()
    {
        return (string)(date('Ymdhms') . '' . dechex(rand(1, 10 ** 12)));
    }

    public static function destroy()
    {
        self::$publicKey = '';
        self::$privateKey = '';
    }
}
