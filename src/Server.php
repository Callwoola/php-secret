<?php
namespace Secret;

class Server
{
    // TODO generate appId and secretKey
    // Transfer package for target
    public function __construct()
    {
        $this->generate();
    }

    public function generate()
    {
    }

    public function revert()
    {

    }

    public function loadClientMessage()
    {
        // load public key from client.
        // Decode
        // get app id
        // get message
        // get callback url
    }
}