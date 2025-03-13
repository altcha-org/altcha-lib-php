<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class Altcha
{
    private static function hash(string $algorithm, string $data): string
    {
        switch ($algorithm) {
            case Algorithm::SHA1:
                return sha1($data, true);
            case Algorithm::SHA256:
                return hash('sha256', $data, true);
            case Algorithm::SHA512:
                return hash('sha512', $data, true);
            default:
                throw new \InvalidArgumentException("Unsupported algorithm: $algorithm");
        }
    }

    public static function hashHex(string $algorithm, string $data): string
    {
        return bin2hex(self::hash($algorithm, $data));
    }

    private static function hmacHash(string $algorithm, string $data, string $key): string
    {
        switch ($algorithm) {
            case Algorithm::SHA1:
                return hash_hmac('sha1', $data, $key, true);
            case Algorithm::SHA256:
                return hash_hmac('sha256', $data, $key, true);
            case Algorithm::SHA512:
                return hash_hmac('sha512', $data, $key, true);
            default:
                throw new \InvalidArgumentException("Unsupported algorithm: $algorithm");
        }
    }

    private static function hmacHex(string $algorithm, string $data, string $key): string
    {
        return bin2hex(self::hmacHash($algorithm, $data, $key));
    }

    /**
     * @return null|array<array-key, mixed>
     */
    private static function decodePayload(string $payload): ?array
    {
        $decoded = base64_decode($payload, true);

        if (!$decoded) {
            return null;
        }

        try {
            $data = json_decode($decoded, true, 2, \JSON_THROW_ON_ERROR);
        } catch (\JsonException|\ValueError $e) {
            return null;
        }

        if (!\is_array($data) || empty($data)) {
            return null;
        }

        return $data;
    }

    /**
     * @param array<array-key, mixed>|string $data
     */
    private static function verifyAndBuildSolutionPayload($data): ?Payload
    {
        if (\is_string($data)) {
            $data = self::decodePayload($data);
        }

        if (null === $data
            || !isset($data['algorithm'], $data['challenge'], $data['number'], $data['salt'], $data['signature'])
            || !\is_string($data['algorithm'])
            || !\is_string($data['challenge'])
            || !\is_int($data['number'])
            || !\is_string($data['salt'])
            || !\is_string($data['signature'])
        ) {
            return null;
        }

        return new Payload($data['algorithm'], $data['challenge'], $data['number'], $data['salt'], $data['signature']);
    }

    /**
     * @param array<array-key, mixed>|string $data
     */
    private static function verifyAndBuildServerSignaturePayload($data): ?ServerSignaturePayload
    {
        if (\is_string($data)) {
            $data = self::decodePayload($data);
        }

        if (null === $data
            || !isset($data['algorithm'], $data['verificationData'], $data['signature'], $data['verified'])
            || !\is_string($data['algorithm'])
            || !\is_string($data['verificationData'])
            || !\is_string($data['signature'])
            || !\is_bool($data['verified'])
        ) {
            return null;
        }

        return new ServerSignaturePayload($data['algorithm'], $data['verificationData'], $data['signature'], $data['verified']);
    }

    /**
     * Creates a new challenge for ALTCHA.
     *
     * @return Challenge The challenge data to be passed to ALTCHA.
     */
    public static function createChallenge(BaseChallengeOptions $options): Challenge
    {
        $challenge = self::hashHex($options->algorithm, $options->salt . $options->number);
        $signature = self::hmacHex($options->algorithm, $challenge, $options->hmacKey);

        return new Challenge($options->algorithm, $challenge, $options->maxNumber, $options->salt, $signature);
    }

    /**
     * Verifies an ALTCHA solution.
     *
     * @param array<array-key, mixed>|string $data         The solution payload to verify.
     * @param string                         $hmacKey      The HMAC key used for verification.
     * @param bool                           $checkExpires Whether to check if the challenge has expired.
     *
     * @return bool True if the solution is valid.
     */
    public static function verifySolution($data, string $hmacKey, bool $checkExpires = true): bool
    {
        $payload = self::verifyAndBuildSolutionPayload($data);

        if (!$payload) {
            return false;
        }

        $params = self::extractParams($payload);
        if ($checkExpires && isset($params['expires']) && is_numeric($params['expires'])) {
            $expireTime = (int) $params['expires'];
            if (time() > $expireTime) {
                return false;
            }
        }

        $challengeOptions = new CheckChallengeOptions(
            $hmacKey,
            $payload->algorithm,
            $payload->salt,
            $payload->number
        );

        $expectedChallenge = self::createChallenge($challengeOptions);

        return $expectedChallenge->challenge === $payload->challenge
            && $expectedChallenge->signature === $payload->signature;
    }

    /**
     * @return array<array-key, array<array-key, mixed>|string>
     */
    private static function extractParams(Payload $payload): array
    {
        $saltParts = explode('?', $payload->salt);
        if (\count($saltParts) > 1) {
            parse_str($saltParts[1], $params);

            return $params;
        }

        return [];
    }

    /**
     * Verifies the hash of form fields.
     *
     * @param array<array-key, mixed> $formData   The form data to hash.
     * @param array<array-key, mixed> $fields     The fields to include in the hash.
     * @param string                  $fieldsHash The expected hash value.
     * @param string                  $algorithm  Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).
     */
    public static function verifyFieldsHash(array $formData, array $fields, string $fieldsHash, string $algorithm): bool
    {
        $lines = [];
        foreach ($fields as $field) {
            $lines[] = $formData[$field] ?? '';
        }
        $joinedData = implode("\n", $lines);
        $computedHash = self::hashHex($algorithm, $joinedData);

        return $computedHash === $fieldsHash;
    }

    /**
     * Verifies the server signature.
     *
     * @param array<array-key, mixed>|string $data    The payload to verify (string or `ServerSignaturePayload` array).
     * @param string                         $hmacKey The HMAC key used for verification.
     */
    public static function verifyServerSignature($data, string $hmacKey): ServerSignatureVerification
    {
        $payload = self::verifyAndBuildServerSignaturePayload($data);

        if (!$payload) {
            return new ServerSignatureVerification(false, null);
        }

        $hash = self::hash($payload->algorithm, $payload->verificationData);
        $expectedSignature = self::hmacHex($payload->algorithm, $hash, $hmacKey);

        parse_str($payload->verificationData, $params);

        $classification = isset($params['classification']) && \is_string($params['classification']) ? $params['classification'] : '';
        $country = isset($params['country']) && \is_string($params['country']) ? $params['country'] : '';
        $detectedLanguage = isset($params['detectedLanguage']) && \is_string($params['detectedLanguage']) ? $params['detectedLanguage'] : '';
        $email = isset($params['email']) && \is_string($params['email']) ? $params['email'] : '';
        $expire = isset($params['expire']) && is_numeric($params['expire']) ? (int) $params['expire'] : 0;
        $fields = isset($params['fields']) && \is_array($params['fields']) ? $params['fields'] : [];
        $fieldsHash = isset($params['fieldsHash']) && \is_string($params['fieldsHash']) ? $params['fieldsHash'] : '';
        $reasons = isset($params['reasons']) && \is_array($params['reasons']) ? $params['reasons'] : [];
        $score = isset($params['score']) && is_numeric($params['score']) ? (float) $params['score'] : 0.0;
        $time = isset($params['time']) && is_numeric($params['time']) ? (int) $params['time'] : 0;
        $verified = isset($params['verified']) && $params['verified'];

        $verificationData = new ServerSignatureVerificationData(
            $classification,
            $country,
            $detectedLanguage,
            $email,
            $expire,
            $fields,
            $fieldsHash,
            $reasons,
            $score,
            $time,
            $verified,
        );

        $now = time();
        $isVerified = $payload->verified && $verificationData->verified
            && $verificationData->expire > $now
            && $payload->signature === $expectedSignature;

        return new ServerSignatureVerification($isVerified, $verificationData);
    }

    /**
     * Finds a solution to the given challenge.
     *
     * @param string $challenge The challenge hash.
     * @param string $salt      The challenge salt.
     * @param string $algorithm Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).
     * @param int    $max       Maximum number to iterate to.
     * @param int    $start     Starting number.
     */
    public static function solveChallenge(string $challenge, string $salt, string $algorithm, int $max, int $start = 0): ?Solution
    {
        $startTime = microtime(true);

        for ($n = $start; $n <= $max; $n++) {
            $hash = self::hashHex($algorithm, $salt . $n);
            if ($hash === $challenge) {
                $took = microtime(true) - $startTime;

                return new Solution($n, $took);
            }
        }

        return null;
    }
}
