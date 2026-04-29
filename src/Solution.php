<?php

namespace AltchaOrg\Altcha;

class Solution
{
    public function __construct(
        public readonly int $counter,
        public readonly string $derivedKey,
        public readonly ?float $time = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $arr = [
            'counter' => $this->counter,
            'derivedKey' => $this->derivedKey,
        ];
        if (null !== $this->time) {
            $arr['time'] = $this->time;
        }

        return $arr;
    }
}
