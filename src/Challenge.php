<?php

namespace AltchaOrg\Altcha;

class Challenge
{
    public $algorithm;
    public $challenge;
    public $maxnumber;
    public $salt;
    public $signature;

    public function __construct($algorithm, $challenge, $maxNumber, $salt, $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->maxnumber = $maxNumber;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
