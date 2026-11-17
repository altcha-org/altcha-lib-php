<?php

namespace AltchaOrg\Altcha;

use AltchaOrg\Altcha\Http\HttpClientInterface;

class VerifyServerOptions
{
    /**
     * @param array<string, mixed>|string $payload      The payload to verify, as received from the client
     *                                                  (either the raw base64 string or a decoded array).
     * @param string                      $url          Full URL of the Sentinel endpoint: `/v2/verify/signature`
     *                                                  (Sentinel v2) or `/v1/verify/signature` (Sentinel v1).
     * @param null|string                 $secret       Sentinel v1 only: API key secret, sent in the request body.
     *                                                  Sentinel checks that it matches the payload's API key.
     *                                                  Not sent when `apiKey` is set; Sentinel v2 rejects it.
     * @param null|HttpClientInterface    $httpClient   Custom HTTP client. Defaults to a built-in stream-based client.
     * @param array<string, string>       $headers      Additional headers to send with the request. Override the
     *                                                  `Authorization` header set from `apiKey`.
     * @param float                       $timeout      Per-attempt request timeout in seconds. Defaults to `10.0`.
     * @param int                         $retries      Number of retry attempts after the first try. Network errors,
     *                                                  5xx responses and invalid bodies are retried; 4xx responses
     *                                                  are not. Defaults to `0`.
     * @param int                         $retryDelay   Base delay in milliseconds between retry attempts. Defaults to `300`.
     * @param RetryBackoff                $retryBackoff Backoff strategy applied to `retryDelay`. Defaults to exponential.
     * @param null|VerifyServerApiKey     $apiKey       Sentinel v2: a `restricted` or `full` API key of the account
     *                                                  that owns the payload's API key, sent as
     *                                                  `Authorization: Basic base64(id:secret)`.
     */
    public function __construct(
        public readonly array|string $payload,
        public readonly string $url,
        public readonly ?string $secret = null,
        public readonly ?HttpClientInterface $httpClient = null,
        public readonly array $headers = [],
        public readonly float $timeout = 10.0,
        public readonly int $retries = 0,
        public readonly int $retryDelay = 300,
        public readonly RetryBackoff $retryBackoff = RetryBackoff::Exponential,
        public readonly ?VerifyServerApiKey $apiKey = null,
    ) {
    }
}
