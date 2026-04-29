<?php

namespace AltchaOrg\Altcha;

use AltchaOrg\Altcha\Algorithm\DeriveKeyInterface;

class Altcha
{
    public function __construct(
        private readonly ?string $hmacSignatureSecret = null,
        private readonly ?string $hmacKeySignatureSecret = null,
        private readonly HmacAlgorithm $hmacAlgorithm = HmacAlgorithm::SHA256,
    ) {
    }

    public function createChallenge(CreateChallengeOptions $options): Challenge
    {
        $nonce = $options->nonce ?? bin2hex(random_bytes(16));
        $salt = $options->salt ?? bin2hex(random_bytes(16));

        $params = new ChallengeParameters(
            algorithm: $options->algorithm->getAlgorithmName(),
            nonce: $nonce,
            salt: $salt,
            cost: $options->cost,
            keyLength: $options->keyLength,
            keyPrefix: $options->keyPrefix,
            memoryCost: $options->memoryCost,
            parallelism: $options->parallelism,
            expiresAt: $options->expiresAt,
            data: $options->data,
        );

        $keyPrefix = $params->keyPrefix;
        $keySignature = null;
        $keyPrefixLength = $options->keyPrefixLength ?? $params->keyLength / 2;

        if (null !== $options->counter) {
            $result = $this->deriveKeyForCounter($options->algorithm, $params, $options->counter);
            $keyPrefix = bin2hex(substr($result, 0, $keyPrefixLength));
            if (null !== $this->hmacKeySignatureSecret) {
                $keySignature = $this->hmacHex(bin2hex($result), $this->hmacKeySignatureSecret);
            }
        } elseif (empty($keyPrefix)) {
            // Generate a random prefix of the desired hex length
            $keyPrefix = bin2hex(random_bytes(max(1, (int) $keyPrefixLength)));
        }

        $params = new ChallengeParameters(
            algorithm: $params->algorithm,
            nonce: $params->nonce,
            salt: $params->salt,
            cost: $params->cost,
            keyLength: $params->keyLength,
            keyPrefix: $keyPrefix,
            keySignature: $keySignature,
            memoryCost: $params->memoryCost,
            parallelism: $params->parallelism,
            expiresAt: $params->expiresAt,
            data: $params->data,
        );

        $signature = $this->hmacSignatureSecret
            ? $this->hmacHex($params->toCanonicalJson(), $this->hmacSignatureSecret)
            : null;

        return new Challenge($params, $signature);
    }

    public function solveChallenge(SolveChallengeOptions $options): ?Solution
    {
        $params = $options->challenge->parameters;
        $nonceBytes = hex2bin($params->nonce) ?: '';
        $saltBytes = hex2bin($params->salt) ?: '';
        $keyPrefixBytes = hex2bin($params->keyPrefix) ?: '';
        $keyPrefixLen = \strlen($keyPrefixBytes);

        $startTime = microtime(true);
        $deadline = $startTime + $options->timeout;
        $i = 0;

        while (microtime(true) < $deadline) {
            $counter = $options->start + ($i * $options->step);
            $password = $nonceBytes . pack('N', $counter);

            $result = $options->algorithm->deriveKey($params, $saltBytes, $password);
            $derivedKey = $result->derivedKey;

            if (substr($derivedKey, 0, $keyPrefixLen) === $keyPrefixBytes) {
                $time = microtime(true) - $startTime;

                return new Solution($counter, bin2hex($derivedKey), $time);
            }

            $i++;
        }

        return null;
    }

    public function verifySolution(VerifySolutionOptions $options): VerifySolutionResult
    {
        $startTime = microtime(true);
        $payload = $options->payload;
        $params = $payload->challenge->parameters;

        // Check expiration
        if (null !== $params->expiresAt) {
            if (time() > $params->expiresAt) {
                return new VerifySolutionResult(
                    verified: false,
                    expired: true,
                    time: microtime(true) - $startTime,
                );
            }
        }

        // Verify challenge signature
        if (null !== $payload->challenge->signature && null !== $this->hmacSignatureSecret) {
            $expectedSignature = $this->hmacHex($params->toCanonicalJson(), $this->hmacSignatureSecret);
            if (!hash_equals($expectedSignature, $payload->challenge->signature)) {
                return new VerifySolutionResult(
                    verified: false,
                    invalidSignature: true,
                    time: microtime(true) - $startTime,
                );
            }
        }

        // Verify solution: fast path via keySignature, or full re-derivation
        if (null !== $params->keySignature && null !== $this->hmacKeySignatureSecret) {
            // Fast path: verify the HMAC of the submitted derived key
            $expectedKeySignature = $this->hmacHex($payload->solution->derivedKey, $this->hmacKeySignatureSecret);
            if (hash_equals($expectedKeySignature, $params->keySignature)) {
                return new VerifySolutionResult(
                    verified: true,
                    time: microtime(true) - $startTime,
                );
            }
        }

        // Full re-derivation path
        $nonceBytes = hex2bin($params->nonce) ?: '';
        $saltBytes = hex2bin($params->salt) ?: '';
        $password = $nonceBytes . pack('N', $payload->solution->counter);

        $result = $options->algorithm->deriveKey($params, $saltBytes, $password);
        $derivedKeyHex = bin2hex($result->derivedKey);

        if (!hash_equals($derivedKeyHex, $payload->solution->derivedKey)) {
            return new VerifySolutionResult(
                verified: false,
                invalidSolution: true,
                time: microtime(true) - $startTime,
            );
        }

        // Verify the derived key starts with the required prefix
        $keyPrefixBytes = hex2bin($params->keyPrefix) ?: '';
        $keyPrefixLen = \strlen($keyPrefixBytes);

        if (substr($result->derivedKey, 0, $keyPrefixLen) !== $keyPrefixBytes) {
            return new VerifySolutionResult(
                verified: false,
                invalidSolution: true,
                time: microtime(true) - $startTime,
            );
        }

        return new VerifySolutionResult(
            verified: true,
            time: microtime(true) - $startTime,
        );
    }

    private function deriveKeyForCounter(DeriveKeyInterface $algorithm, ChallengeParameters $params, int $counter): string
    {
        $nonceBytes = hex2bin($params->nonce) ?: '';
        $saltBytes = hex2bin($params->salt) ?: '';
        $password = $nonceBytes . pack('N', $counter);

        $result = $algorithm->deriveKey($params, $saltBytes, $password);

        return $result->derivedKey;
    }

    private function hmacHex(string $data, string $key): string
    {
        return bin2hex(hash_hmac($this->hmacAlgorithm->hashAlgo(), $data, $key, true));
    }
}
