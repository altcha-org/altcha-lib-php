<?php

namespace AltchaOrg\Altcha;

class Solution
{
    public $number;
    public $took;

    public function __construct($number, $took)
    {
        $this->number = $number;
        $this->took = $took;
    }
}
