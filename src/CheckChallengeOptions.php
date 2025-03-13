<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class CheckChallengeOptions extends BaseChallengeOptions
{
    public function __construct(
        string $hmacKey,
        string $algorithm,
        string $salt,
        int $number,
    ) {
        parent::__construct($algorithm, $hmacKey, self::DEFAULT_MAX_NUMBER, null, $salt, $number, []);
    }
}
