<?php
namespace Secret;

class Client
{
    public $clientPBK = '';
    public $clientPVK = '';

    public function __construct()
    {
        $this->generate();
    }

    public function generate()
    {
        $appID = '';
        $secret = '';
        $this->generateKey();

        return [$appID, $secret];
    }

    public function generateID()
    {

    }





}