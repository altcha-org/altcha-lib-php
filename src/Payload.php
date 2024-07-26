<?php

namespace AltchaOrg\Altcha;

class Payload
{
    public $algorithm;
    public $challenge;
    public $number;
    public $salt;
    public $signature;

    public function __construct($algorithm, $challenge, $number, $salt, $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->number = $number;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
