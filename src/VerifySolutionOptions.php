<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

use AltchaOrg\Altcha\Algorithm\DeriveKeyInterface;

class VerifySolutionOptions
{
    public function __construct(
        public readonly Payload $payload,
        public readonly DeriveKeyInterface $algorithm,
    ) {
    }
}
