<?php

/**
 * Example ALTCHA server for client-side challenge verification.
 *
 * This example demonstrates the typical flow where a client (browser) fetches
 * a challenge, solves it, and submits the solution along with form data.
 *
 * Endpoints:
 *   GET  /challenge  - Create a new challenge (JSON response)
 *   POST /submit     - Handle form submission (application/x-www-form-urlencoded)
 *                       The "altcha" field contains a base64-encoded payload
 *                       (server signature or client solution, auto-detected).
 *
 * Usage:
 *   php -S localhost:8080 examples/server.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\ServerSignature;
use AltchaOrg\Altcha\VerifySolutionOptions;

// -- Configuration --

$hmacSecret = getenv('ALTCHA_HMAC_SECRET') ?: 'example-hmac-secret';
$pbkdf2 = new Pbkdf2();
$altcha = new Altcha($hmacSecret);

// -- CORS --

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
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
        $method === 'GET' && $path === '/challenge' => handleChallenge($altcha, $pbkdf2),
        $method === 'POST' && $path === '/submit' => handleSubmit($altcha, $pbkdf2, $hmacSecret),
        default => sendJson(['error' => 'Not found'], 404),
    };
} catch (\Throwable $e) {
    sendJson(['error' => $e->getMessage()], 500);
}

// -- Handlers --

function handleChallenge(Altcha $altcha, Pbkdf2 $pbkdf2): void
{
    $challenge = $altcha->createChallenge(new CreateChallengeOptions(
        algorithm: $pbkdf2,
        cost: 10000,
        expiresAt: time() + 120,
    ));

    sendJson($challenge->toArray());
}

function handleSubmit(Altcha $altcha, Pbkdf2 $pbkdf2, string $hmacSecret): void
{
    $altchaField = $_POST['altcha'] ?? null;

    if (!is_string($altchaField) || $altchaField === '') {
        sendJson(['error' => 'Missing "altcha" form field'], 400);
        return;
    }

    // Decode just enough to auto-detect the payload type:
    //   Server signature: has "verificationData"
    //   Client solution:  has "challenge" + "solution"
    $decoded = base64_decode($altchaField, true);
    $payload = $decoded === false ? null : json_decode($decoded, true);
    if (!is_array($payload)) {
        sendJson(['error' => 'Invalid "altcha" field'], 400);
        return;
    }

    try {
        if (isset($payload['verificationData'])) {
            $result = ServerSignature::verifyServerSignature($payload, $hmacSecret);
            $verified = $result->verified;
        } elseif (isset($payload['challenge'], $payload['solution'])) {
            // The library accepts the raw base64 string, a decoded array, or a
            // Payload object directly — no manual parsing required.
            $result = $altcha->verifySolution(new VerifySolutionOptions(
                payload: $payload,
                algorithm: $pbkdf2,
            ));
            $verified = $result->verified;
        } else {
            sendJson(['error' => 'Unrecognized payload format'], 400);
            return;
        }
    } catch (\InvalidArgumentException $e) {
        sendJson(['error' => $e->getMessage()], 400);
        return;
    }

    if (!$verified) {
        sendJson([
            'error' => 'Verification failed',
            'verification' => $result,
        ], 403);
        return;
    }

    // Payload verified — process form data
    $formData = $_POST;

    sendJson([
        'data' => $formData,
        'verification' => $result,
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
