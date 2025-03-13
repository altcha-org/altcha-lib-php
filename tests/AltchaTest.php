<?php

use AltchaOrg\Altcha\Algorithm;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\BaseChallengeOptions;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\ChallengeOptions;
use AltchaOrg\Altcha\Solution;
use PHPUnit\Framework\TestCase;

class AltchaTest extends TestCase
{
    private static Challenge $challenge;

    public static function setUpBeforeClass(): void
    {
        // build a default challenge for all tests (for performance reasons)
        $options = new ChallengeOptions('test-key');
        self::$challenge = Altcha::createChallenge($options);
    }

    public function testCreateChallenge(): void
    {
        self::assertEquals(Algorithm::SHA256, self::$challenge->algorithm);
        self::assertNotEmpty(self::$challenge->challenge);
        self::assertEquals(BaseChallengeOptions::DEFAULT_MAX_NUMBER, self::$challenge->maxnumber);
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
        $fieldsHash = Altcha::hashHex(Algorithm::SHA256, "value1\nvalue2");

        $isValid = Altcha::verifyFieldsHash($formData, $fields, $fieldsHash, Algorithm::SHA256);

        self::assertTrue($isValid);
    }

    public function testSolveChallenge(): void
    {
        $solution = Altcha::solveChallenge(
            self::$challenge->challenge,
            self::$challenge->salt,
            self::$challenge->algorithm,
            self::$challenge->maxnumber
        );

        self::assertInstanceOf(Solution::class, $solution);
        self::assertEquals($solution->number, $solution->number);
        self::assertGreaterThan(0, $solution->took);
    }

    public function testVerifySolution(): void
    {
        $solution = Altcha::solveChallenge(
            self::$challenge->challenge,
            self::$challenge->salt,
            self::$challenge->algorithm,
            self::$challenge->maxnumber
        );

        self::assertInstanceOf(Solution::class, $solution);

        $payload = [
            'algorithm' => self::$challenge->algorithm,
            'challenge' => self::$challenge->challenge,
            'salt' => self::$challenge->salt,
            'signature' => self::$challenge->signature,
            'number' => $solution->number,
        ];

        $isValid = Altcha::verifySolution($payload, 'test-key');

        self::assertTrue($isValid);
    }

    public function testInvalidPayload(): void
    {
        $isValid = Altcha::verifySolution('I am invalid', 'key');
        self::assertFalse($isValid);

        $verification = Altcha::verifyServerSignature('I am invalid', 'key');
        self::assertFalse($verification->verified);
    }
}
