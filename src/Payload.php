<?php

namespace AltchaOrg\Altcha;

class Payload
{
    public function __construct(
        public readonly Challenge $challenge,
        public readonly Solution $solution,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'challenge' => $this->challenge->toArray(),
            'solution' => $this->solution->toArray(),
        ];
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE) ?: '';
    }

    public function toBase64(): string
    {
        return base64_encode($this->toJson());
    }
}
