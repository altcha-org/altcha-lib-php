<?php

use PHPUnit\Framework\TestCase;
use AltchaOrg\Altcha\Algorithm;
use AltchaOrg\Altcha\ChallengeOptions;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\Solution;

class AltchaTest extends TestCase
{
    public function testCreateChallenge()
    {
        $options = new ChallengeOptions([
            'algorithm' => Algorithm::SHA256,
            'hmacKey' => 'test-key'
        ]);

        $challenge = Altcha::createChallenge($options);

        $this->assertInstanceOf(Challenge::class, $challenge);
        $this->assertEquals(Algorithm::SHA256, $challenge->algorithm);
        $this->assertNotEmpty($challenge->challenge);
        $this->assertEquals(1e6, $challenge->maxnumber);
        $this->assertNotEmpty($challenge->salt);
        $this->assertNotEmpty($challenge->signature);
    }

    public function testVerifySolution()
    {
        $options = new ChallengeOptions([
            'algorithm' => Algorithm::SHA256,
            'number' => 10,
            'hmacKey' => 'test-key'
        ]);

        $challenge = Altcha::createChallenge($options);
        $payload = [
            'algorithm' => $challenge->algorithm,
            'challenge' => $challenge->challenge,
            'number' => 10,
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
        ];

        $isValid = Altcha::verifySolution($payload, 'test-key');

        $this->assertTrue($isValid);
    }

    public function testVerifyFieldsHash()
    {
        $formData = [
            'field1' => 'value1',
            'field2' => 'value2'
        ];

        $fields = ['field1', 'field2'];
        $fieldsHash = Altcha::hashHex(Algorithm::SHA256, "value1\nvalue2");

        $isValid = Altcha::verifyFieldsHash($formData, $fields, $fieldsHash, Algorithm::SHA256);

        $this->assertTrue($isValid);
    }

    public function testSolveChallenge()
    {
        $options = new ChallengeOptions([
            'algorithm' => Algorithm::SHA256,
            'hmacKey' => 'test-key',
            'maxNumber' => 100
        ]);

        $challenge = Altcha::createChallenge($options);

        $solution = Altcha::solveChallenge($challenge->challenge, $challenge->salt, $challenge->algorithm, $challenge->maxnumber);

        $this->assertInstanceOf(Solution::class, $solution);
        $this->assertEquals($solution->number, $solution->number);
        $this->assertGreaterThan(0, $solution->took);
    }
}
