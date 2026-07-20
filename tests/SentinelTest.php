<?php

namespace AltchaOrg\Altcha\Tests;

use AltchaOrg\Altcha\Http\HttpResponse;
use AltchaOrg\Altcha\RetryBackoff;
use AltchaOrg\Altcha\Sentinel;
use AltchaOrg\Altcha\Tests\Support\FakeHttpClient;
use AltchaOrg\Altcha\VerifyServerOptions;
use PHPUnit\Framework\TestCase;

class SentinelTest extends TestCase
{
    public function testVerifyServerSuccess(): void
    {
        $client = new FakeHttpClient([
            new HttpResponse(200, json_encode([
                'verified' => true,
                'apiKey' => 'key_1',
                'verificationData' => ['verified' => true, 'score' => 0.1],
            ]) ?: ''),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
        ));

        self::assertTrue($result->verified);
        self::assertEquals('key_1', $result->apiKey);
        self::assertNotNull($result->verificationData);
        self::assertTrue($result->verificationData->verified);
        self::assertEquals(1, $client->callCount);
    }

    public function testVerifyServerSendsPayloadAndSecretInBody(): void
    {
        $client = new FakeHttpClient([
            new HttpResponse(200, json_encode(['verified' => true]) ?: ''),
        ]);

        Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            secret: 'sec_123',
            httpClient: $client,
        ));

        $sentBody = json_decode($client->requestBodies[0], true);
        self::assertEquals(['payload' => 'payload-str', 'secret' => 'sec_123'], $sentBody);
        self::assertEquals('application/json', $client->requestHeaders[0]['Content-Type']);
    }

    public function testVerifyServerOmitsSecretWhenNotProvided(): void
    {
        $client = new FakeHttpClient([
            new HttpResponse(200, json_encode(['verified' => true]) ?: ''),
        ]);

        Sentinel::verify(new VerifyServerOptions(
            payload: ['challenge' => 'x'],
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
        ));

        /** @var array<string, mixed> $sentBody */
        $sentBody = json_decode($client->requestBodies[0], true);
        self::assertArrayNotHasKey('secret', $sentBody);
        self::assertEquals(['challenge' => 'x'], $sentBody['payload']);
    }

    public function testVerifyServerFailureWithoutExceptionIsReturnedAsIs(): void
    {
        $client = new FakeHttpClient([
            new HttpResponse(200, json_encode(['verified' => false, 'reason' => 'PAYLOAD_ALREADY_USED']) ?: ''),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
        ));

        self::assertFalse($result->verified);
        self::assertEquals('PAYLOAD_ALREADY_USED', $result->reason);
        self::assertEquals(1, $client->callCount);
    }

    public function testVerifyServer400IsTerminalAndNotRetried(): void
    {
        $client = new FakeHttpClient([
            new HttpResponse(400, json_encode(['error' => 'INVALID_PAYLOAD']) ?: ''),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
            retries: 3,
        ));

        self::assertFalse($result->verified);
        self::assertEquals('INVALID_PAYLOAD', $result->reason);
        self::assertEquals(1, $client->callCount);
    }

    public function testVerifyServerRetriesExhaustedOnNetworkFailure(): void
    {
        $client = new FakeHttpClient([
            new \RuntimeException('fetch failed'),
            new \RuntimeException('fetch failed'),
            new \RuntimeException('fetch failed'),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
            retries: 2,
            retryDelay: 1,
        ));

        self::assertFalse($result->verified);
        self::assertEquals('fetch failed', $result->reason);
        self::assertEquals(3, $client->callCount);
    }

    public function testVerifyServerRetriesThenSucceeds(): void
    {
        $client = new FakeHttpClient([
            new \RuntimeException('fetch failed'),
            new HttpResponse(200, json_encode(['verified' => true]) ?: ''),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
            retries: 1,
            retryDelay: 1,
            retryBackoff: RetryBackoff::Fixed,
        ));

        self::assertTrue($result->verified);
        self::assertEquals(2, $client->callCount);
    }

    public function testVerifyServerRetriesOnNon2xxNon400Status(): void
    {
        $client = new FakeHttpClient([
            new HttpResponse(500, 'Internal Server Error'),
            new HttpResponse(200, json_encode(['verified' => true]) ?: ''),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
            retries: 1,
            retryDelay: 1,
        ));

        self::assertTrue($result->verified);
        self::assertEquals(2, $client->callCount);
    }

    public function testVerifyServerNoRetriesByDefault(): void
    {
        $client = new FakeHttpClient([
            new \RuntimeException('fetch failed'),
        ]);

        $result = Sentinel::verify(new VerifyServerOptions(
            payload: 'payload-str',
            url: 'https://sentinel.example.com/v1/verify/signature',
            httpClient: $client,
        ));

        self::assertFalse($result->verified);
        self::assertEquals(1, $client->callCount);
    }
}
