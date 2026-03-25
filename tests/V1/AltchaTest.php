<?php

namespace AltchaOrg\Altcha\Tests\V1;

use AltchaOrg\Altcha\V1\Altcha;
use AltchaOrg\Altcha\V1\BaseChallengeOptions;
use AltchaOrg\Altcha\V1\Challenge;
use AltchaOrg\Altcha\V1\ChallengeOptions;
use AltchaOrg\Altcha\V1\Hasher\Algorithm;
use AltchaOrg\Altcha\V1\Hasher\Hasher;
use AltchaOrg\Altcha\V1\Obfuscator;
use AltchaOrg\Altcha\V1\Solution;
use PHPUnit\Framework\TestCase;

class AltchaTest extends TestCase
{
    private static Hasher $hasher;
    private static Altcha $altcha;
    private static Challenge $challenge;

    public static function setUpBeforeClass(): void
    {
        // build a default challenge for all tests (for performance reasons)
        self::$hasher = new Hasher();
        self::$altcha = new Altcha('test-key', self::$hasher);
        self::$challenge = self::$altcha->createChallenge();
    }

    public function testCreateChallenge(): void
    {
        self::assertEquals(Algorithm::SHA256->value, self::$challenge->algorithm);
        self::assertNotEmpty(self::$challenge->challenge);
        self::assertEquals(BaseChallengeOptions::DEFAULT_MAX_NUMBER, self::$challenge->maxNumber);
        self::assertNotEmpty(self::$challenge->salt);
        self::assertNotEmpty(self::$challenge->signature);
    }

    public function testVerifyFieldsHash(): void
    {
        $formData = [
            'field1' => 'value1',
            'field2' => 'value2',
        ];

        $fields = ['field1', 'field2'];
        $fieldsHash = '1e823fb92790112edaa34e8cfed2afbb86054153932d8c2796d2c62727d287a6';

        $isValid = self::$altcha->verifyFieldsHash($formData, $fields, $fieldsHash, Algorithm::SHA256);

        self::assertTrue($isValid);
    }

    public function testSolveChallenge(): void
    {
        $solution = self::$altcha->solveChallenge(
            self::$challenge->challenge,
            self::$challenge->salt,
            Algorithm::from(self::$challenge->algorithm),
            self::$challenge->maxNumber
        );

        self::assertInstanceOf(Solution::class, $solution);
        self::assertEquals($solution->number, $solution->number);
        self::assertGreaterThan(0, $solution->took);
    }

    public function testInvalidSolveChallenge(): void
    {
        $solution = self::$altcha->solveChallenge(
            'asd',
            self::$challenge->salt,
            Algorithm::from(self::$challenge->algorithm),
            self::$challenge->maxNumber
        );

        self::assertNull($solution);
    }

    public function testVerifySolution(): void
    {
        $solution = self::$altcha->solveChallenge(
            self::$challenge->challenge,
            self::$challenge->salt,
            Algorithm::from(self::$challenge->algorithm),
            self::$challenge->maxNumber
        );

        self::assertInstanceOf(Solution::class, $solution);

        $payload = [
            'algorithm' => self::$challenge->algorithm,
            'challenge' => self::$challenge->challenge,
            'salt' => self::$challenge->salt,
            'signature' => self::$challenge->signature,
            'number' => $solution->number,
        ];

        $isValid = self::$altcha->verifySolution(base64_encode(json_encode($payload) ?: ''));

        self::assertTrue($isValid);
    }

    public function testVerifySolutionSaltSplicing(): void
    {
        $challenge = self::$altcha->createChallenge(new BaseChallengeOptions(
            algorithm: Algorithm::SHA256,
            maxNumber: 50000,
            number: 123,
            expires: (new \DateTimeImmutable())->add(new \DateInterval('PT10S')),
            params: [],
            salt: bin2hex(random_bytes(12)),
        ));

        $payload = [
            'algorithm' => $challenge->algorithm,
            'challenge' => $challenge->challenge,
            'salt' => $challenge->salt . '1',
            'signature' => $challenge->signature,
            'number' => 23,
        ];

        $isValid = self::$altcha->verifySolution(base64_encode(json_encode($payload) ?: ''));

        self::assertFalse($isValid);
    }

    public function testVerifyServerSignature(): void
    {
        $algorithm = Algorithm::SHA256;
        $expires = (new \DateTimeImmutable())->add(new \DateInterval('PT10S'));
        $verificationData = 'verified=1&expire=' . $expires->getTimestamp();

        $hash = self::$hasher->hash($algorithm, $verificationData);
        $signature = self::$hasher->hashHmacHex($algorithm, $hash, 'test-key');

        $result = self::$altcha->verifyServerSignature([
            'algorithm' => $algorithm->value,
            'verificationData' => $verificationData,
            'signature' => $signature,
            'verified' => true,
        ]);

        self::assertTrue($result->verified);
    }

    public function testVerifyCustomOptions(): void
    {
        $maxNumber = 100;
        $algorithm = Algorithm::SHA1;

        $challenge = self::$altcha->createChallenge(new ChallengeOptions(
            algorithm: $algorithm,
            maxNumber: $maxNumber,
            expires: (new \DateTimeImmutable())->add(new \DateInterval('PT10S')),
            params: ['custom_param' => '123'],
            saltLength: 3,
        ));

        $solution = self::$altcha->solveChallenge(
            $challenge->challenge,
            $challenge->salt,
            $algorithm,
            $maxNumber,
        );

        self::assertInstanceOf(Solution::class, $solution);

        $isValid = self::$altcha->verifySolution([
            'algorithm' => $algorithm->value,
            'challenge' => $challenge->challenge,
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
            'number' => $solution->number,
        ]);

        self::assertTrue($isValid);
    }

    public function testHandlesExpired(): void
    {
        $maxNumber = 100;
        $expires = (new \DateTimeImmutable())->sub(new \DateInterval('PT10S'));

        $challenge = self::$altcha->createChallenge(new ChallengeOptions(
            maxNumber: $maxNumber,
            expires: $expires,
        ));

        $solution = self::$altcha->solveChallenge(
            $challenge->challenge,
            $challenge->salt,
            Algorithm::from($challenge->algorithm),
            $maxNumber,
        );

        self::assertInstanceOf(Solution::class, $solution);

        $isValid = self::$altcha->verifySolution([
            'algorithm' => $challenge->algorithm,
            'challenge' => $challenge->challenge,
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
            'number' => $solution->number,
        ]);

        self::assertFalse($isValid);
    }

    public function testInvalidPayloads(): void
    {
        // completely invalid string
        $isValid = self::$altcha->verifySolution('I am invalid');
        self::assertFalse($isValid);

        // invalid base64 string
        $isValid = self::$altcha->verifySolution('$' . base64_encode('I am invalid'));
        self::assertFalse($isValid);

        // invalid JSON string
        $isValid = self::$altcha->verifySolution(base64_encode('I am invalid'));
        self::assertFalse($isValid);

        // invalid JSON data
        $isValid = self::$altcha->verifySolution(base64_encode('"I am not an array"'));
        self::assertFalse($isValid);

        $isValid = self::$altcha->verifySolution([
            'algorithm' => 'md5',
            'challenge' => 'invalid',
            'salt' => 'salt',
            'signature' => 'signature',
            'number' => 10,
        ]);
        self::assertFalse($isValid);

        $verification = self::$altcha->verifyServerSignature('I am invalid');
        self::assertFalse($verification->verified);

        $verification = self::$altcha->verifyServerSignature([
            'algorithm' => 'md5',
            'verificationData' => 'asd',
            'signature' => 'signature',
            'verified' => true,
        ]);
        self::assertFalse($verification->verified);
    }

    public function testDataObfuscation(): void
    {
        $obfuscator = new Obfuscator();
        $counter = 1234;

        $email = 'mailto:hello@example.com';
        $address = 'Big Company Ltd.' . \PHP_EOL . '123 Baker Street' . \PHP_EOL . 'London' . \PHP_EOL . 'NW1 6XE' . \PHP_EOL . 'United Kingdom';

        $obfuscatedEmail = $obfuscator->obfuscateData($email, '', $counter);
        $obfuscatedAddress = $obfuscator->obfuscateData($address, '', $counter);

        self::assertEquals('0WkWnouD/fos4DdkwHP2yQ1/UejeYYUjP2vtH+F5+s8PYTJcvup6mg==', $obfuscatedEmail);
        self::assertEquals('/mEY0ryDquIo4iIrzGLqhmo+D77QQIslSwgQNW1ojHqPmhU6DxlmZfKkXAfiCR2BabAg7E/K7kPttHA/c5sDe08H1tR822PCVNxRwGbVOg==', $obfuscatedAddress);

        $key = 'shared-secret';

        $obfuscatedEmailWithKey = $obfuscator->obfuscateData($email, $key, $counter);
        $obfuscatedAddressWithKey = $obfuscator->obfuscateData($address, $key, $counter);

        self::assertEquals('VYjBMLSjm0dasqAtnQvSlRiqG0V0paCoLFtNPZTB5jwmjPmV2Ja41w==', $obfuscatedEmailWithKey);
        self::assertEquals('eoDPfIOjzF9esLVikRrO2n/rRRN6hK6ug4cwoWDJHYS9++OfBQjOUMP9oBHiGbNR0+3pj2whifZf/Cixj6oG+ybIQjx/t2apDsSLwr4qKg==', $obfuscatedAddressWithKey);
    }
}
