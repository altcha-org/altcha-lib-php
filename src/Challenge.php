<?php

namespace AltchaOrg\Altcha;

class Challenge
{
    public function __construct(
        public readonly ChallengeParameters $parameters,
        public readonly ?string $signature = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $arr = ['parameters' => $this->parameters->toArray()];
        if (null !== $this->signature) {
            $arr['signature'] = $this->signature;
        }

        return $arr;
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE) ?: '';
    }
}
