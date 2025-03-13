<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

/**
 * @phpstan-type ChallengeParams array<string, null|scalar>
 */
class BaseChallengeOptions
{
    public const DEFAULT_MAX_NUMBER = 1000000;

    public string $algorithm;
    public int $maxNumber;
    public string $hmacKey;
    public string $salt;
    public int $number;
    public ?\DateTimeInterface $expires;

    /** @var array<array-key, null|scalar> */
    public array $params;

    /**
     * Options for creation of a new challenge.
     *
     * @see ChallengeOptions for options with sane defaults.
     *
     * @param ChallengeParams $params
     */
    public function __construct(
        string $algorithm,
        string $hmacKey,
        int $maxNumber,
        ?\DateTimeInterface $expires,
        string $salt,
        int $number,
        array $params,
    ) {
        $this->algorithm = $algorithm;
        $this->hmacKey = $hmacKey;
        $this->maxNumber = $maxNumber;
        $this->expires = $expires;
        $this->salt = $salt;
        $this->number = $number;
        $this->params = $params;

        if ($expires) {
            $params['expires'] = $expires->getTimestamp();
        }

        if (!empty($params)) {
            $this->salt .= '?' . http_build_query($params);
        }
    }
}
