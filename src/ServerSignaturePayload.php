<?php

namespace AltchaOrg\Altcha;

class ServerSignaturePayload
{
    public $algorithm;
    public $verificationData;
    public $signature;
    public $verified;

    public function __construct($algorithm, $verificationData, $signature, $verified)
    {
        $this->algorithm = $algorithm;
        $this->verificationData = $verificationData;
        $this->signature = $signature;
        $this->verified = $verified;
    }
}
