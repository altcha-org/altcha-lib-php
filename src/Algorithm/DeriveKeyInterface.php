<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha\Algorithm;

use AltchaOrg\Altcha\ChallengeParameters;

interface DeriveKeyInterface
{
    public function getAlgorithmName(): string;

    public function deriveKey(
        ChallengeParameters $parameters,
        string $salt,
        string $password,
    ): DeriveKeyResult;
}
