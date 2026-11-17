<?php

namespace AltchaOrg\Altcha;

use AltchaOrg\Altcha\Http\HttpResponse;
use AltchaOrg\Altcha\Http\StreamHttpClient;

class Sentinel
{
    /**
     * Verifies a payload remotely via the ALTCHA Sentinel API, instead of verifying the
     * HMAC signature locally: Sentinel v2's `/v2/verify/signature` (authenticated with
     * `apiKey`) or Sentinel v1's `/v1/verify/signature` (with the optional `secret`).
     */
    public static function verify(VerifyServerOptions $options): VerifyServerResult
    {
        $httpClient = $options->httpClient ?? new StreamHttpClient();

        // `secret` is only understood by a v1 Sentinel; Sentinel v2 rejects it next to credentials.
        $body = ['payload' => $options->payload];
        if (null === $options->apiKey && null !== $options->secret) {
            $body['secret'] = $options->secret;
        }
        $bodyJson = json_encode($body, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE) ?: '{}';

        $headers = ['Content-Type' => 'application/json'];
        if (null !== $options->apiKey) {
            $headers['Authorization'] = 'Basic ' . base64_encode($options->apiKey->id . ':' . $options->apiKey->secret);
        }
        $headers = [...$headers, ...$options->headers];

        for ($attempt = 0; $attempt <= $options->retries; $attempt++) {
            try {
                $response = $httpClient->send($options->url, 'POST', $headers, $bodyJson, $options->timeout);

                return self::handleResponse($response);
            } catch (\Throwable $e) {
                if ($attempt >= $options->retries) {
                    return new VerifyServerResult(verified: false, reason: $e->getMessage());
                }

                $backoffMs = RetryBackoff::Fixed === $options->retryBackoff
                    ? $options->retryDelay
                    : $options->retryDelay * 2 ** $attempt;
                usleep($backoffMs * 1000);
            }
        }

        return new VerifyServerResult(verified: false, reason: 'NETWORK_ERROR');
    }

    /**
     * Interprets an HTTP response. Returns a terminal (non-retryable) VerifyServerResult for
     * 2xx and 4xx statuses, or throws to trigger the retry path for other statuses and
     * unparseable bodies.
     */
    private static function handleResponse(HttpResponse $response): VerifyServerResult
    {
        if ($response->statusCode < 200 || $response->statusCode >= 300) {
            $reason = self::errorReason($response);
            // A 4xx (bad payload, bad credentials, wrong account) fails the same way again.
            if ($response->statusCode >= 400 && $response->statusCode < 500) {
                return new VerifyServerResult(verified: false, reason: $reason);
            }

            throw new \RuntimeException($reason);
        }

        $data = json_decode($response->body, true);
        if (!\is_array($data)) {
            throw new \RuntimeException('Invalid JSON response from Sentinel API.');
        }

        /** @var array<string, mixed> $result */
        $result = $data;

        return VerifyServerResult::fromArray($result);
    }

    /**
     * The `code` of a Sentinel error body (`{code, error, statusCode}`), else its `error`
     * (a v1 Sentinel sends only `error`), else `HTTP_<status>`.
     */
    private static function errorReason(HttpResponse $response): string
    {
        $data = json_decode($response->body, true);
        if (\is_array($data)) {
            if (isset($data['code']) && \is_string($data['code']) && '' !== $data['code']) {
                return $data['code'];
            }
            if (isset($data['error']) && \is_string($data['error']) && '' !== $data['error']) {
                return $data['error'];
            }
        }

        return 'HTTP_' . $response->statusCode;
    }
}
