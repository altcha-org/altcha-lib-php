<?php

namespace AltchaOrg\Altcha;

class ChallengeParameters
{
    /**
     * @param null|array<string, mixed> $data
     */
    public function __construct(
        public readonly string $algorithm,
        public readonly string $nonce,
        public readonly string $salt,
        public readonly int $cost,
        public readonly int $keyLength = 32,
        public readonly string $keyPrefix = '',
        public readonly ?string $keySignature = null,
        public readonly ?int $memoryCost = null,
        public readonly ?int $parallelism = null,
        public readonly ?int $expiresAt = null,
        public readonly ?array $data = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $arr = [
            'algorithm' => $this->algorithm,
            'cost' => $this->cost,
            'keyLength' => $this->keyLength,
            'keyPrefix' => $this->keyPrefix,
            'nonce' => $this->nonce,
            'salt' => $this->salt,
        ];

        if (null !== $this->keySignature) {
            $arr['keySignature'] = $this->keySignature;
        }
        if (null !== $this->memoryCost) {
            $arr['memoryCost'] = $this->memoryCost;
        }
        if (null !== $this->parallelism) {
            $arr['parallelism'] = $this->parallelism;
        }
        if (null !== $this->expiresAt) {
            $arr['expiresAt'] = $this->expiresAt;
        }
        if (null !== $this->data) {
            $arr['data'] = $this->data;
        }

        ksort($arr);

        return $arr;
    }

    public function toCanonicalJson(): string
    {
        return self::canonicalJson($this->toArray());
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function canonicalJson(array $data): string
    {
        ksort($data);
        self::sortRecursive($data);

        return json_encode($data, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE) ?: '';
    }

    /**
     * @param array<mixed> $data
     */
    private static function sortRecursive(array &$data): void
    {
        foreach ($data as &$value) {
            if (\is_array($value) && !array_is_list($value)) {
                ksort($value);
                self::sortRecursive($value);
            }
        }
    }

    /**
     * @param array<string, mixed> $arr
     */
    public static function fromArray(array $arr): self
    {
        $algorithm = isset($arr['algorithm']) && \is_string($arr['algorithm']) ? $arr['algorithm'] : '';
        $nonce = isset($arr['nonce']) && \is_string($arr['nonce']) ? $arr['nonce'] : '';
        $salt = isset($arr['salt']) && \is_string($arr['salt']) ? $arr['salt'] : '';
        $cost = isset($arr['cost']) && \is_int($arr['cost']) ? $arr['cost'] : 0;
        $keyLength = isset($arr['keyLength']) && \is_int($arr['keyLength']) ? $arr['keyLength'] : 32;
        $keyPrefix = isset($arr['keyPrefix']) && \is_string($arr['keyPrefix']) ? $arr['keyPrefix'] : '';
        $keySignature = isset($arr['keySignature']) && \is_string($arr['keySignature']) ? $arr['keySignature'] : null;
        $memoryCost = isset($arr['memoryCost']) && \is_int($arr['memoryCost']) ? $arr['memoryCost'] : null;
        $parallelism = isset($arr['parallelism']) && \is_int($arr['parallelism']) ? $arr['parallelism'] : null;
        $expiresAt = isset($arr['expiresAt']) && \is_int($arr['expiresAt']) ? $arr['expiresAt'] : null;
        /** @var null|array<string, mixed> $data */
        $data = isset($arr['data']) && \is_array($arr['data']) ? $arr['data'] : null;

        return new self(
            algorithm: $algorithm,
            nonce: $nonce,
            salt: $salt,
            cost: $cost,
            keyLength: $keyLength,
            keyPrefix: $keyPrefix,
            keySignature: $keySignature,
            memoryCost: $memoryCost,
            parallelism: $parallelism,
            expiresAt: $expiresAt,
            data: $data,
        );
    }
}
