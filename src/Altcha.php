<?php

namespace AltchaOrg\Altcha;

use InvalidArgumentException;

class Altcha
{
    const DEFAULT_MAX_NUMBER = 1e6;
    const DEFAULT_SALT_LENGTH = 12;
    const DEFAULT_ALGORITHM = Algorithm::SHA256;

    private static function randomBytes($length)
    {
        return random_bytes($length);
    }

    private static function randomInt($max)
    {
        return random_int(0, $max);
    }

    private static function hash($algorithm, $data)
    {
        switch ($algorithm) {
            case Algorithm::SHA1:
                return sha1($data, true);
            case Algorithm::SHA256:
                return hash('sha256', $data, true);
            case Algorithm::SHA512:
                return hash('sha512', $data, true);
            default:
                throw new InvalidArgumentException("Unsupported algorithm: $algorithm");
        }
    }

    public static function hashHex($algorithm, $data)
    {
        return bin2hex(self::hash($algorithm, $data));
    }

    private static function hmacHash($algorithm, $data, $key)
    {
        switch ($algorithm) {
            case Algorithm::SHA1:
                return hash_hmac('sha1', $data, $key, true);
            case Algorithm::SHA256:
                return hash_hmac('sha256', $data, $key, true);
            case Algorithm::SHA512:
                return hash_hmac('sha512', $data, $key, true);
            default:
                throw new InvalidArgumentException("Unsupported algorithm: $algorithm");
        }
    }

    private static function hmacHex($algorithm, $data, $key)
    {
        return bin2hex(self::hmacHash($algorithm, $data, $key));
    }

    public static function createChallenge($options)
    {
        if (is_array($options)) {
            $options = new ChallengeOptions($options);
        }

        $algorithm = $options->algorithm ?: self::DEFAULT_ALGORITHM;
        $maxNumber = $options->maxNumber ?: self::DEFAULT_MAX_NUMBER;
        $saltLength = $options->saltLength ?: self::DEFAULT_SALT_LENGTH;

        $params = $options->params;
        if ($options->expires) {
            $params['expires'] = $options->expires->getTimestamp();
        }

        $salt = $options->salt ?: bin2hex(self::randomBytes($saltLength));
        if (!empty($params)) {
            $salt .= '?' . http_build_query($params);
        }

        $number = $options->number ?: self::randomInt($maxNumber);

        $challenge = self::hashHex($algorithm, $salt . $number);

        $signature = self::hmacHex($algorithm, $challenge, $options->hmacKey);

        return new Challenge($algorithm, $challenge, $maxNumber, $salt, $signature);
    }

    public static function verifySolution($payload, $hmacKey, $checkExpires = true)
    {
        if (is_string($payload)) {
            $payload = json_decode(base64_decode($payload), true);
        }

        $payload = new Payload($payload['algorithm'], $payload['challenge'], $payload['number'], $payload['salt'], $payload['signature']);

        $params = self::extractParams($payload);
        if ($checkExpires && isset($params['expires'])) {
            $expireTime = (int)$params['expires'];
            if (time() > $expireTime) {
                return false;
            }
        }

        $challengeOptions = new ChallengeOptions([
            'algorithm' => $payload->algorithm,
            'hmacKey' => $hmacKey,
            'number' => $payload->number,
            'salt' => $payload->salt,
        ]);

        $expectedChallenge = self::createChallenge($challengeOptions);

        return $expectedChallenge->challenge === $payload->challenge &&
            $expectedChallenge->signature === $payload->signature;
    }

    private static function extractParams($payload)
    {
        $saltParts = explode('?', $payload->salt);
        if (count($saltParts) > 1) {
            parse_str($saltParts[1], $params);
            return $params;
        }
        return [];
    }

    public static function verifyFieldsHash($formData, $fields, $fieldsHash, $algorithm)
    {
        $lines = [];
        foreach ($fields as $field) {
            $lines[] = $formData[$field] ?? '';
        }
        $joinedData = implode("\n", $lines);
        $computedHash = self::hashHex($algorithm, $joinedData);
        return $computedHash === $fieldsHash;
    }

    public static function verifyServerSignature($payload, $hmacKey)
    {
        if (is_string($payload)) {
            $payload = json_decode(base64_decode($payload), true);
        }

        $payload = new ServerSignaturePayload($payload['algorithm'], $payload['verificationData'], $payload['signature'], $payload['verified']);

        $hash = self::hash($payload->algorithm, $payload->verificationData);
        $expectedSignature = self::hmacHex($payload->algorithm, $hash, $hmacKey);

        parse_str($payload->verificationData, $params);

        $verificationData = new ServerSignatureVerificationData();
        $verificationData->classification = $params['classification'] ?? '';
        $verificationData->country = $params['country'] ?? '';
        $verificationData->detectedLanguage = $params['detectedLanguage'] ?? '';
        $verificationData->email = $params['email'] ?? '';
        $verificationData->expire = (int)($params['expire'] ?? 0);
        $verificationData->fields = explode(',', $params['fields'] ?? '');
        $verificationData->fieldsHash = $params['fieldsHash'] ?? '';
        $verificationData->reasons = explode(',', $params['reasons'] ?? '');
        $verificationData->score = (float)($params['score'] ?? 0);
        $verificationData->time = (int)($params['time'] ?? 0);
        $verificationData->verified = ($params['verified'] ?? 'false') === 'true';

        $now = time();
        $isVerified = $payload->verified && $verificationData->verified &&
            $verificationData->expire > $now &&
            $payload->signature === $expectedSignature;

        return [$isVerified, $verificationData];
    }

    public static function solveChallenge($challenge, $salt, $algorithm, $max = 1000000, $start = 0)
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
