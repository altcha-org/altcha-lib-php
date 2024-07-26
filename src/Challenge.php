<?php

namespace AltchaOrg\Altcha;

class Challenge
{
    public $algorithm;
    public $challenge;
    public $maxNumber;
    public $salt;
    public $signature;

    public function __construct($algorithm, $challenge, $maxNumber, $salt, $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->maxNumber = $maxNumber;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
