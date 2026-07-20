<?php

/**
 * Example ALTCHA server using Sentinel for remote verification.
 *
 * This example demonstrates a server that verifies form submissions
 * remotely by calling Sentinel's `/v1/verify/signature` API, instead of
 * verifying the HMAC signature locally. No hmacSignatureSecret is needed
 * on this server — point the widget's `challengeurl` at your Sentinel
 * instance instead, since it issues and signs challenges directly.
 *
 * Endpoints:
 *   POST /submit  - Handle form submission (application/x-www-form-urlencoded)
 *                    The "altcha" field contains the base64-encoded payload,
 *                    verified remotely via Sentinel.
 *
 * Usage:
 *   ALTCHA_SENTINEL_URL=https://sentinel.example.com/v1/verify/signature \
 *   ALTCHA_SENTINEL_SECRET=sec_... \
 *   php -S localhost:8080 examples/server_sentinel.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AltchaOrg\Altcha\Sentinel;
use AltchaOrg\Altcha\VerifyServerOptions;

// -- Configuration --

$sentinelUrl = getenv('ALTCHA_SENTINEL_URL') ?: 'https://sentinel.example.com/v1/verify/signature';
$sentinelSecret = getenv('ALTCHA_SENTINEL_SECRET') ?: null;

// -- CORS --

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// -- Routing --

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($method === 'OPTIONS') {
    http_response_code(204);
    return;
}

try {
    match (true) {
        $method === 'POST' && $path === '/submit' => handleSubmit($sentinelUrl, $sentinelSecret),
        default => sendJson(['error' => 'Not found'], 404),
    };
} catch (\Throwable $e) {
    sendJson(['error' => $e->getMessage()], 500);
}

// -- Handlers --

function handleSubmit(string $sentinelUrl, ?string $sentinelSecret): void
{
    $altchaField = $_POST['altcha'] ?? null;

    if (!is_string($altchaField) || $altchaField === '') {
        sendJson(['error' => 'Missing "altcha" form field'], 400);
        return;
    }

    $result = Sentinel::verify(new VerifyServerOptions(
        payload: $altchaField,
        url: $sentinelUrl,
        secret: $sentinelSecret,
        timeout: 10.0,
        retries: 2,
    ));

    if (!$result->verified) {
        sendJson([
            'error' => 'Verification failed',
            'reason' => $result->reason,
        ], 403);
        return;
    }

    // Payload verified — process form data
    $formData = $_POST;
    unset($formData['altcha']);

    sendJson([
        'data' => $formData,
        'verification' => [
            'verified' => $result->verified,
            'apiKey' => $result->apiKey,
            'verificationData' => $result->verificationData?->toArray(),
        ],
    ]);
}

// -- Helpers --

/**
 * @param array<string, mixed> $data
 */
function sendJson(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
}
