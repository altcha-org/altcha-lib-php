<?php

namespace AltchaOrg\Altcha\Tests\Support;

use AltchaOrg\Altcha\Http\HttpClientInterface;
use AltchaOrg\Altcha\Http\HttpResponse;

/**
 * Test double that returns (or throws) queued responses in order, recording each request made.
 */
class FakeHttpClient implements HttpClientInterface
{
    public int $callCount = 0;

    /** @var list<string> */
    public array $requestedUrls = [];

    /** @var list<string> */
    public array $requestBodies = [];

    /** @var list<array<string, string>> */
    public array $requestHeaders = [];

    /**
     * @param list<HttpResponse|\Throwable> $queue
     */
    public function __construct(private array $queue)
    {
    }

    public function send(string $url, string $method, array $headers, string $body, float $timeout): HttpResponse
    {
        $this->callCount++;
        $this->requestedUrls[] = $url;
        $this->requestBodies[] = $body;
        $this->requestHeaders[] = $headers;

        $next = array_shift($this->queue);
        if (null === $next) {
            throw new \RuntimeException('FakeHttpClient: no more responses queued.');
        }

        if ($next instanceof \Throwable) {
            throw $next;
        }

        return $next;
    }
}
