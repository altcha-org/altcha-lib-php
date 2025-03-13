<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class ServerSignatureVerificationData
{
    public string $classification;
    public string $country;
    public string $detectedLanguage;
    public string $email;
    public int $expire;
    /** @var array<array-key, mixed> */
    public array $fields;
    public string $fieldsHash;
    /** @var array<array-key, mixed> */
    public array $reasons;
    public float $score;
    public int $time;
    public bool $verified;

    /**
     * @param array<array-key, mixed> $fields
     * @param array<array-key, mixed> $reasons
     */
    public function __construct(
        string $classification,
        string $country,
        string $detectedLanguage,
        string $email,
        int $expire,
        array $fields,
        string $fieldsHash,
        array $reasons,
        float $score,
        int $time,
        bool $verified,
    ) {
        $this->classification = $classification;
        $this->country = $country;
        $this->detectedLanguage = $detectedLanguage;
        $this->email = $email;
        $this->expire = $expire;
        $this->fields = $fields;
        $this->fieldsHash = $fieldsHash;
        $this->reasons = $reasons;
        $this->score = $score;
        $this->time = $time;
        $this->verified = $verified;
    }
}
