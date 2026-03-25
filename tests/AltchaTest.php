<?php

namespace AltchaOrg\Altcha\Tests;

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Algorithm\Sha;
use AltchaOrg\Altcha\Algorithm\ShaAlgorithm;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\ChallengeParameters;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\HmacAlgorithm;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\ServerSignature;
use AltchaOrg\Altcha\Solution;
use AltchaOrg\Altcha\SolveChallengeOptions;
use AltchaOrg\Altcha\VerifySolutionOptions;
use PHPUnit\Framework\TestCase;

class AltchaTest extends TestCase
{
    private Altcha $altcha;
    private Pbkdf2 $pbkdf2;

    protected function setUp(): void
    {
        $this->pbkdf2 = new Pbkdf2();
        $this->altcha = new Altcha('test-secret', 'test-key-secret');
    }

    public function testCreateChallenge(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 1000,
            keyPrefixLength: 1,
        ));

        self::assertEquals('PBKDF2/SHA-256', $challenge->parameters->algorithm);
        self::assertNotEmpty($challenge->parameters->nonce);
        self::assertNotEmpty($challenge->parameters->salt);
        self::assertEquals(1000, $challenge->parameters->cost);
        self::assertEquals(32, $challenge->parameters->keyLength);
        self::assertNotEmpty($challenge->parameters->keyPrefix);
        self::assertNotNull($challenge->signature);
    }

    public function testCreateChallengeDeterministic(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 1000,
            keyPrefixLength: 1,
            counter: 42,
            nonce: 'aabbccdd00112233aabbccdd00112233',
            salt: '11223344556677889900aabbccddeeff',
        ));

        self::assertEquals('aabbccdd00112233aabbccdd00112233', $challenge->parameters->nonce);
        self::assertEquals('11223344556677889900aabbccddeeff', $challenge->parameters->salt);
        self::assertNotNull($challenge->parameters->keySignature);

        // The prefix should be derived from the actual key
        self::assertNotEmpty($challenge->parameters->keyPrefix);
    }

    public function testSolveAndVerifyRoundTrip(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
            counter: 5,
        ));

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $this->pbkdf2,
        ));

        self::assertInstanceOf(Solution::class, $solution);
        self::assertNotEmpty($solution->derivedKey);
        self::assertNotNull($solution->time);
        self::assertGreaterThanOrEqual(0, $solution->time);

        $payload = new Payload($challenge, $solution);
        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $this->pbkdf2,
        ));

        self::assertTrue($result->verified);
        self::assertFalse($result->expired);
        self::assertNull($result->invalidSignature);
        self::assertNull($result->invalidSolution);
    }

    public function testSolveWithRandomPrefix(): void
    {
        // Non-deterministic: random prefix, solver must search
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
        ));

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $this->pbkdf2,
        ));

        // With 1-byte prefix (256 possibilities), should almost always find a match
        self::assertInstanceOf(Solution::class, $solution);

        $payload = new Payload($challenge, $solution);

        // Verify without keySignature (no hmacKeySignatureSecret for random prefix)
        $altchaNoKeySecret = new Altcha('test-secret');
        $challenge2 = $altchaNoKeySecret->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
        ));

        $solution2 = $altchaNoKeySecret->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge2,
            algorithm: $this->pbkdf2,
        ));

        if (null !== $solution2) {
            $payload2 = new Payload($challenge2, $solution2);
            $result2 = $altchaNoKeySecret->verifySolution(new VerifySolutionOptions(
                payload: $payload2,
                algorithm: $this->pbkdf2,
            ));
            self::assertTrue($result2->verified);
        }
    }

    public function testExpiration(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
            counter: 5,
            expiresAt: time() - 10, // expired 10 seconds ago
        ));

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $this->pbkdf2,
        ));

        self::assertInstanceOf(Solution::class, $solution);

        $payload = new Payload($challenge, $solution);
        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $this->pbkdf2,
        ));

        self::assertFalse($result->verified);
        self::assertTrue($result->expired);
    }

    public function testInvalidSignature(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
            counter: 5,
        ));

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $this->pbkdf2,
        ));

        self::assertInstanceOf(Solution::class, $solution);

        // Tamper with the challenge signature
        $tamperedChallenge = new Challenge($challenge->parameters, 'invalid_signature');
        $payload = new Payload($tamperedChallenge, $solution);

        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $this->pbkdf2,
        ));

        self::assertFalse($result->verified);
        self::assertTrue($result->invalidSignature);
    }

    public function testInvalidSolution(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
            counter: 5,
        ));

        // Create a fake solution with wrong counter
        $fakeSolution = new Solution(999999, 'deadbeef');
        $payload = new Payload($challenge, $fakeSolution);

        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $this->pbkdf2,
        ));

        self::assertFalse($result->verified);
        self::assertTrue($result->invalidSolution);
    }

    public function testChallengeParametersCanonicalJson(): void
    {
        $params = new ChallengeParameters(
            algorithm: 'PBKDF2/SHA-256',
            nonce: 'abc123',
            salt: 'def456',
            cost: 1000,
            keyLength: 32,
            keyPrefix: 'ff',
        );

        $json = $params->toCanonicalJson();
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($json, true);

        // Keys should be sorted
        $keys = array_keys($decoded);
        $sortedKeys = $keys;
        sort($sortedKeys);
        self::assertEquals($sortedKeys, $keys);

        self::assertEquals('PBKDF2/SHA-256', $decoded['algorithm']);
        self::assertEquals(1000, $decoded['cost']);
    }

    public function testChallengeParametersFromArray(): void
    {
        $arr = [
            'algorithm' => 'PBKDF2/SHA-256',
            'nonce' => 'abc',
            'salt' => 'def',
            'cost' => 500,
            'keyLength' => 16,
            'keyPrefix' => 'aa',
            'expiresAt' => 1234567890,
            'data' => ['foo' => 'bar'],
        ];

        $params = ChallengeParameters::fromArray($arr);

        self::assertEquals('PBKDF2/SHA-256', $params->algorithm);
        self::assertEquals('abc', $params->nonce);
        self::assertEquals('def', $params->salt);
        self::assertEquals(500, $params->cost);
        self::assertEquals(16, $params->keyLength);
        self::assertEquals('aa', $params->keyPrefix);
        self::assertEquals(1234567890, $params->expiresAt);
        self::assertEquals(['foo' => 'bar'], $params->data);
    }

    public function testPbkdf2DeriveKey(): void
    {
        $params = new ChallengeParameters(
            algorithm: 'PBKDF2/SHA-256',
            nonce: 'aabb',
            salt: 'ccdd',
            cost: 1000,
            keyLength: 32,
            keyPrefix: '',
        );

        $result = $this->pbkdf2->deriveKey($params, (string) hex2bin('ccdd'), (string) hex2bin('aabb') . pack('N', 0));

        self::assertEquals(32, \strlen($result->derivedKey));
        self::assertNull($result->parameterOverrides);
    }

    public function testPbkdf2Sha384(): void
    {
        $pbkdf2 = new Pbkdf2(HmacAlgorithm::SHA384);

        self::assertEquals('PBKDF2/SHA-384', $pbkdf2->getAlgorithmName());

        $params = new ChallengeParameters(
            algorithm: 'PBKDF2/SHA-384',
            nonce: 'aabb',
            salt: 'ccdd',
            cost: 100,
            keyLength: 48,
            keyPrefix: '',
        );

        $result = $pbkdf2->deriveKey($params, (string) hex2bin('ccdd'), (string) hex2bin('aabb') . pack('N', 0));
        self::assertEquals(48, \strlen($result->derivedKey));
    }

    public function testPbkdf2Sha512(): void
    {
        $pbkdf2 = new Pbkdf2(HmacAlgorithm::SHA512);

        self::assertEquals('PBKDF2/SHA-512', $pbkdf2->getAlgorithmName());
    }

    public function testPayloadSerialization(): void
    {
        $params = new ChallengeParameters(
            algorithm: 'PBKDF2/SHA-256',
            nonce: 'abc',
            salt: 'def',
            cost: 100,
            keyLength: 32,
            keyPrefix: 'ff',
        );
        $challenge = new Challenge($params, 'sig123');
        $solution = new Solution(42, 'deadbeef', 0.5);

        $payload = new Payload($challenge, $solution);

        $json = $payload->toJson();
        /** @var array<string, array<string, mixed>> $decoded */
        $decoded = json_decode($json, true);

        self::assertArrayHasKey('challenge', $decoded);
        self::assertArrayHasKey('solution', $decoded);
        self::assertEquals(42, $decoded['solution']['counter']);
        self::assertEquals('deadbeef', $decoded['solution']['derivedKey']);

        $base64 = $payload->toBase64();
        self::assertEquals($json, base64_decode($base64));
    }

    public function testVerifySolutionWithKeySignatureFastPath(): void
    {
        // Deterministic mode generates keySignature for fast verification
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
            counter: 10,
        ));

        self::assertNotNull($challenge->parameters->keySignature);

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $this->pbkdf2,
        ));

        self::assertInstanceOf(Solution::class, $solution);

        $payload = new Payload($challenge, $solution);
        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $this->pbkdf2,
        ));

        self::assertTrue($result->verified);
    }

    public function testServerSignatureVerification(): void
    {
        $hmacKey = 'server-secret';
        $algorithm = HmacAlgorithm::SHA256;
        $expires = time() + 60;
        $verificationData = 'verified=true&expire=' . $expires . '&score=0.5&fields=field1,field2&classification=GOOD';

        $hash = hash($algorithm->hashAlgo(), $verificationData, true);
        $signature = bin2hex(hash_hmac($algorithm->hashAlgo(), $hash, $hmacKey, true));

        $result = ServerSignature::verifyServerSignature([
            'algorithm' => $algorithm->value,
            'verificationData' => $verificationData,
            'signature' => $signature,
            'verified' => true,
        ], $hmacKey);

        self::assertTrue($result->verified);
        self::assertFalse($result->expired);
        self::assertFalse($result->invalidSignature);
        self::assertFalse($result->invalidSolution);
        self::assertGreaterThan(0.0, $result->time);
        self::assertNotNull($result->verificationData);
        self::assertTrue($result->verificationData->verified);
        self::assertEquals($expires, $result->verificationData->expire);
        self::assertEquals(0.5, $result->verificationData->score);
        self::assertEquals(['field1', 'field2'], $result->verificationData->fields);
        self::assertEquals('GOOD', $result->verificationData->classification);
        self::assertEquals('GOOD', $result->verificationData['classification']);
    }

    public function testServerSignatureInvalid(): void
    {
        $result = ServerSignature::verifyServerSignature('invalid', 'key');
        self::assertFalse($result->verified);

        $result = ServerSignature::verifyServerSignature([
            'algorithm' => 'md5',
            'verificationData' => 'asd',
            'signature' => 'sig',
            'verified' => true,
        ], 'key');
        self::assertFalse($result->verified);
    }

    public function testServerSignatureExpired(): void
    {
        $hmacKey = 'server-secret';
        $algorithm = HmacAlgorithm::SHA256;
        $expires = time() - 60; // expired
        $verificationData = 'verified=true&expire=' . $expires;

        $hash = hash($algorithm->hashAlgo(), $verificationData, true);
        $signature = bin2hex(hash_hmac($algorithm->hashAlgo(), $hash, $hmacKey, true));

        $result = ServerSignature::verifyServerSignature([
            'algorithm' => $algorithm->value,
            'verificationData' => $verificationData,
            'signature' => $signature,
            'verified' => true,
        ], $hmacKey);

        self::assertFalse($result->verified);
        self::assertTrue($result->expired);
        self::assertFalse($result->invalidSignature);
        self::assertFalse($result->invalidSolution);
    }

    public function testVerifyFieldsHash(): void
    {
        $formData = [
            'field1' => 'value1',
            'field2' => 'value2',
        ];

        $fields = ['field1', 'field2'];
        $fieldsHash = hash('sha256', "value1\nvalue2");

        $isValid = ServerSignature::verifyFieldsHash($formData, $fields, $fieldsHash);

        self::assertTrue($isValid);
    }

    public function testChallengeWithData(): void
    {
        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $this->pbkdf2,
            cost: 100,
            keyPrefixLength: 1,
            counter: 1,
            data: ['foo' => 'bar'],
        ));

        self::assertEquals(['foo' => 'bar'], $challenge->parameters->data);

        $json = $challenge->parameters->toCanonicalJson();
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($json, true);
        self::assertEquals(['foo' => 'bar'], $decoded['data']);
    }

    public function testShaAlgorithmNames(): void
    {
        self::assertEquals('SHA-1', (new Sha(ShaAlgorithm::SHA1))->getAlgorithmName());
        self::assertEquals('SHA-256', (new Sha(ShaAlgorithm::SHA256))->getAlgorithmName());
        self::assertEquals('SHA-384', (new Sha(ShaAlgorithm::SHA384))->getAlgorithmName());
        self::assertEquals('SHA-512', (new Sha(ShaAlgorithm::SHA512))->getAlgorithmName());
    }

    public function testShaDeriveKey(): void
    {
        $sha = new Sha(ShaAlgorithm::SHA256);

        $params = new ChallengeParameters(
            algorithm: 'SHA-256',
            nonce: 'aabb',
            salt: 'ccdd',
            cost: 0,
            keyLength: 32,
            keyPrefix: '',
        );

        $result = $sha->deriveKey($params, (string) hex2bin('ccdd'), (string) hex2bin('aabb') . pack('N', 0));

        self::assertEquals(32, \strlen($result->derivedKey));
        self::assertNull($result->parameterOverrides);
    }

    public function testShaSolveAndVerifyRoundTrip(): void
    {
        $sha = new Sha(ShaAlgorithm::SHA256);

        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $sha,
            cost: 0,
            keyPrefixLength: 1,
            counter: 5,
        ));

        self::assertEquals('SHA-256', $challenge->parameters->algorithm);

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $sha,
        ));

        self::assertInstanceOf(Solution::class, $solution);

        $payload = new Payload($challenge, $solution);
        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $sha,
        ));

        self::assertTrue($result->verified);
    }

    public function testSha512RoundTrip(): void
    {
        $sha = new Sha(ShaAlgorithm::SHA512);

        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $sha,
            cost: 0,
            keyLength: 64,
            keyPrefixLength: 1,
            counter: 3,
        ));

        self::assertEquals('SHA-512', $challenge->parameters->algorithm);

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $sha,
        ));

        self::assertInstanceOf(Solution::class, $solution);

        $payload = new Payload($challenge, $solution);
        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $sha,
        ));

        self::assertTrue($result->verified);
    }

    public function testSha1RoundTrip(): void
    {
        $sha = new Sha(ShaAlgorithm::SHA1);

        $challenge = $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: $sha,
            cost: 0,
            keyLength: 20,
            keyPrefixLength: 1,
            counter: 7,
        ));

        self::assertEquals('SHA-1', $challenge->parameters->algorithm);

        $solution = $this->altcha->solveChallenge(new SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $sha,
        ));

        self::assertInstanceOf(Solution::class, $solution);

        $payload = new Payload($challenge, $solution);
        $result = $this->altcha->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: $sha,
        ));

        self::assertTrue($result->verified);
    }

    public function testHmacAlgorithmEnum(): void
    {
        self::assertEquals('SHA-256', HmacAlgorithm::SHA256->value);
        self::assertEquals('SHA-384', HmacAlgorithm::SHA384->value);
        self::assertEquals('SHA-512', HmacAlgorithm::SHA512->value);

        self::assertEquals('sha256', HmacAlgorithm::SHA256->hashAlgo());
        self::assertEquals('sha384', HmacAlgorithm::SHA384->hashAlgo());
        self::assertEquals('sha512', HmacAlgorithm::SHA512->hashAlgo());
    }

    public function testChallengeToJson(): void
    {
        $params = new ChallengeParameters(
            algorithm: 'PBKDF2/SHA-256',
            nonce: 'abc',
            salt: 'def',
            cost: 100,
            keyLength: 32,
            keyPrefix: 'ff',
        );
        $challenge = new Challenge($params, 'signature');

        $json = $challenge->toJson();
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($json, true);

        self::assertArrayHasKey('parameters', $decoded);
        self::assertArrayHasKey('signature', $decoded);
        self::assertEquals('signature', $decoded['signature']);
    }
}
