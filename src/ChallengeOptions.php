<?php

namespace AltchaOrg\Altcha;

class ChallengeOptions
{
    public $algorithm;
    public $maxNumber;
    public $saltLength;
    public $hmacKey;
    public $salt;
    public $number;
    public $expires;
    public $params;

    public function __construct($options = [])
    {
        $this->algorithm = $options['algorithm'] ?? Algorithm::SHA256;
        $this->maxNumber = $options['maxNumber'] ?? 1e6;
        $this->saltLength = $options['saltLength'] ?? 12;
        $this->hmacKey = $options['hmacKey'] ?? '';
        $this->salt = $options['salt'] ?? '';
        $this->number = $options['number'] ?? 0;
        $this->expires = $options['expires'] ?? null;
        $this->params = $options['params'] ?? [];
    }
}
