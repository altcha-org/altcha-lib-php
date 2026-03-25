<?php

/**
 * Example ALTCHA server verification.
 *
 * This example demonstrates a server that only verifies server signature
 * payloads such as ALTCHA Sentinel payloads.
 * No client challenge flow is involved.
 *
 * Endpoints:
 *   POST /verify  - Verify a server signature payload
 *
 * Usage:
 *   php -S localhost:8080 examples/server_verify.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AltchaOrg\Altcha\ServerSignature;

// -- Configuration --

$hmacSecret = getenv('ALTCHA_HMAC_SECRET') ?: 'example-hmac-secret';

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
        $method === 'POST' && $path === '/verify' => handleVerify($hmacSecret),
        default => sendJson(['error' => 'Not found'], 404),
    };
} catch (\Throwable $e) {
    sendJson(['error' => $e->getMessage()], 500);
}

// -- Handlers --

function handleVerify(string $hmacSecret): void
{
    $body = readJsonBody();

    if (!isset($body['payload'])) {
        sendJson(['error' => 'Missing "payload" field'], 400);
        return;
    }

    // Accepts both a base64-encoded string and a JSON object
    $result = ServerSignature::verifyServerSignature($body['payload'], $hmacSecret);

    sendJson([
        'verified' => $result->verified,
        'expired' => $result->expired,
        'invalidSignature' => $result->invalidSignature,
        'invalidSolution' => $result->invalidSolution,
        'time' => $result->time,
        'verificationData' => $result->verificationData?->toArray(),
    ]);
}

// -- Helpers --

/**
 * @return array<string, mixed>
 */
function readJsonBody(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        sendJson(['error' => 'Empty request body'], 400);
        exit;
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        sendJson(['error' => 'Invalid JSON'], 400);
        exit;
    }

    return $data;
}

/**
 * @param array<string, mixed> $data
 */
function sendJson(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
}
