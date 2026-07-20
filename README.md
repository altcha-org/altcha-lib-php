# ALTCHA PHP Library

A lightweight PHP library for creating and verifying [ALTCHA](https://altcha.org) challenges using key derivation functions (PBKDF2, Argon2id, Scrypt).

## Compatibility

- PHP 8.1+

## Migrating from V1 to V2

- [`MIGRATION-v1.md`](/MIGRATION-v1.md)

## Example

- [Basic Server](/examples/server.php)
- [Server Signature](/examples/server_verify.php)
- [ALTCHA Sentinel](/examples/server_sentinel.php)

## Installation

```sh
composer require altcha-org/altcha
```

## Usage

```php
<?php

require 'vendor/autoload.php';

use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\SolveChallengeOptions;
use AltchaOrg\Altcha\VerifySolutionOptions;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\Algorithm\Pbkdf2;

$pbkdf2 = new Pbkdf2();
$altcha = new Altcha(
    hmacSignatureSecret: 'secret',
    hmacKeySignatureSecret: 'key-secret', // optional, enables fast verification path
);

// Create a new challenge
// Modify the cost and counter depending on the algorithm
$challenge = $altcha->createChallenge(new CreateChallengeOptions(
    algorithm: $pbkdf2,
    cost: 5000,
    counter: random_int(5000, 10000),
    expiresAt: time() + 600,
));

// Solve the challenge (client-side in production)
$solution = $altcha->solveChallenge(new SolveChallengeOptions(
    algorithm: $pbkdf2,
    challenge: $challenge,
));

// Verify the solution (server-side)
if ($solution !== null) {
    $payload = new Payload($challenge, $solution);
    $result = $altcha->verifySolution(new VerifySolutionOptions(
        algorithm: $pbkdf2,
        payload: $payload,
    ));

    if ($result->verified) {
        echo "Solution verified!\n";
    }
}
```

`VerifySolutionOptions::$payload` also accepts the raw base64-encoded string posted by the widget, or a decoded associative array — no manual parsing required:

```php
// $_POST['altcha'] is the base64-encoded payload string from the widget
$result = $altcha->verifySolution(new VerifySolutionOptions(
    payload: $_POST['altcha'],
    algorithm: $pbkdf2,
));
```

## API

### `Altcha`

```php
$altcha = new Altcha(
    hmacSignatureSecret: 'secret',
    hmacKeySignatureSecret: 'key-secret', // enables fast verification path
    hmacAlgorithm: HmacAlgorithm::SHA256, // default
);
```

### `Altcha::createChallenge(CreateChallengeOptions $options): Challenge`

Creates a new challenge.

#### `CreateChallengeOptions`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `DeriveKeyInterface` | required | Key derivation algorithm |
| `cost` | `int` | required | Iterations/time cost |
| `counter` | `?int` | `null` | Counter for deterministic mode |
| `data` | `?array` | `null` | Custom metadata |
| `expiresAt` | `?int` | `null` | Unix timestamp for expiration |
| `keyLength` | `int` | `32` | Derived key length in bytes |
| `keyPrefixLength` | `int` | `keyLength / 2` | Key prefix length in bytes |
| `memoryCost` | `?int` | `null` | Memory cost (Argon2id/Scrypt) |
| `nonce` | `?string` | `null` | Custom nonce (hex) |
| `parallelism` | `?int` | `null` | Parallelism factor (Scrypt) |
| `salt` | `?string` | `null` | Custom salt (hex) |

When `counter` is provided and `hmacKeySignatureSecret` is set, the challenge includes a `keySignature` for fast verification (skips re-derivation).

**Returns:** `Challenge` with `parameters` (`ChallengeParameters`) and `signature`.

### `Altcha::solveChallenge(SolveChallengeOptions $options): ?Solution`

Iterates counter values to find a derived key matching the challenge prefix.

#### `SolveChallengeOptions`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `DeriveKeyInterface` | required | Key derivation algorithm |
| `challenge` | `Challenge` | required | The challenge to solve |
| `start` | `int` | `0` | Initial counter value |
| `step` | `int` | `1` | Counter increment per iteration |
| `timeout` | `float` | `30.0` | Timeout in seconds |

**Returns:** `Solution` with `counter`, `derivedKey` (hex), and `time` (seconds). Returns `null` if no match is found.

### `Altcha::verifySolution(VerifySolutionOptions $options): VerifySolutionResult`

Verifies a solution against its challenge.

#### `VerifySolutionOptions`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `DeriveKeyInterface` | required | Key derivation algorithm |
| `payload` | `Payload\|string\|array` | required | Challenge + solution pair — a `Payload` object, a raw base64-encoded payload string (as posted by the widget), or a decoded associative array. Throws `InvalidArgumentException` if a string/array can't be parsed into a valid payload. |

#### `VerifySolutionResult`

| Property | Type | Description |
|---|---|---|
| `verified` | `bool` | Whether the solution is valid |
| `expired` | `bool` | Whether the challenge has expired |
| `invalidSignature` | `?bool` | Whether the challenge signature is invalid |
| `invalidSolution` | `?bool` | Whether the derived key doesn't match |
| `time` | `float` | Verification time in seconds |

### Key Derivation Algorithms

All algorithms implement `DeriveKeyInterface`.

#### PBKDF2

```php
use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\HmacAlgorithm;

new Pbkdf2();                        // PBKDF2/SHA-256
new Pbkdf2(HmacAlgorithm::SHA384);  // PBKDF2/SHA-384
new Pbkdf2(HmacAlgorithm::SHA512);  // PBKDF2/SHA-512
```

#### Argon2id

Requires `ext-sodium` (typically bundled with PHP).

```php
use AltchaOrg\Altcha\Algorithm\Argon2id;

new Argon2id();
```

Uses `memoryCost` from challenge options.

#### Scrypt

Requires `ext-scrypt` ([php-scrypt](https://github.com/DomBlack/php-scrypt)).

```php
use AltchaOrg\Altcha\Algorithm\Scrypt;

new Scrypt();
```

Uses `memoryCost` (r, default: 8) and `parallelism` (p, default: 1) from challenge options.

### `HmacAlgorithm`

Enum used for HMAC signing and PBKDF2 hash selection:

- `HmacAlgorithm::SHA256` - `SHA-256`
- `HmacAlgorithm::SHA384` - `SHA-384`
- `HmacAlgorithm::SHA512` - `SHA-512`

### `ServerSignature::verifyServerSignature(string|array $data, string $hmacKey, HmacAlgorithm $hmacAlgorithm = HmacAlgorithm::SHA256): ServerSignatureVerification`

Verifies a server signature payload.

#### `ServerSignatureVerification`

| Property | Type | Description |
|---|---|---|
| `verified` | `bool` | Whether the signature is valid, not expired, and solution verified |
| `expired` | `bool` | Whether the verification data has expired |
| `invalidSignature` | `bool` | Whether the HMAC signature is invalid |
| `invalidSolution` | `bool` | Whether the solution was not verified |
| `time` | `float` | Verification time in seconds |
| `verificationData` | `?ServerSignatureVerificationData` | Parsed verification data |

Verification data is parsed generically from URL-encoded params with auto-detected types (`bool`, `int`, `float`, `string`, `array` for `fields`/`reasons`). Access values via property or array syntax:

```php
use AltchaOrg\Altcha\ServerSignature;

$result = ServerSignature::verifyServerSignature($payload, 'server-secret');

if ($result->verified) {
    $result->verificationData->expire;          // int
    $result->verificationData->score;           // float
    $result->verificationData->verified;        // bool
    $result->verificationData->fields;          // array
    $result->verificationData->classification;  // string
    $result->verificationData['email'];         // array access also works
}
```

### `ServerSignature::verifyFieldsHash(array $formData, array $fields, string $fieldsHash, HmacAlgorithm $hmacAlgorithm = HmacAlgorithm::SHA256): bool`

Verifies the hash of specific form fields.

```php
$isValid = ServerSignature::verifyFieldsHash(
    formData: ['name' => 'John', 'email' => 'john@example.com'],
    fields: ['name', 'email'],
    fieldsHash: hash('sha256', "John\njohn@example.com"),
);
```

### `Sentinel::verify(VerifyServerOptions $options): VerifyServerResult`

Verifies a payload remotely by calling [ALTCHA Sentinel](https://altcha.org)'s `POST /v1/verify/signature` API, instead of verifying the HMAC signature locally. Useful when Sentinel issues and signs challenges directly, so your server doesn't need to hold the HMAC secret at all.

```php
use AltchaOrg\Altcha\Sentinel;
use AltchaOrg\Altcha\VerifyServerOptions;

$result = Sentinel::verify(new VerifyServerOptions(
    payload: $_POST['altcha'], // raw base64 string, or a decoded array
    url: 'https://sentinel.example.com/v1/verify/signature',
    secret: $sentinelApiKeySecret, // optional, checked against the payload's API key
    timeout: 10.0,
    retries: 2,
));

if ($result->verified) {
    // ...
}
```

#### `VerifyServerOptions`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `payload` | `string\|array` | required | The payload to verify, as received from the client (raw base64 string or decoded array) |
| `url` | `string` | required | Full URL of the Sentinel `/v1/verify/signature` endpoint |
| `secret` | `?string` | `null` | API key secret checked against the payload's API key |
| `httpClient` | `?HttpClientInterface` | `null` | Custom HTTP client. Defaults to a built-in stream-based client requiring no extra extension |
| `headers` | `array<string, string>` | `[]` | Additional headers to send with the request |
| `timeout` | `float` | `10.0` | Per-attempt request timeout in seconds |
| `retries` | `int` | `0` | Number of retry attempts after the first try |
| `retryDelay` | `int` | `300` | Base delay in milliseconds between retries |
| `retryBackoff` | `RetryBackoff` | `RetryBackoff::Exponential` | Backoff strategy (`Fixed` or `Exponential`) applied to `retryDelay` |

A `4xx`/non-2xx HTTP response and network errors are retried up to `retries` times (with backoff), except HTTP `400`, which is treated as a definitive verification failure and returned immediately.

#### `VerifyServerResult`

| Property | Type | Description |
|---|---|---|
| `verified` | `bool` | Whether the payload was successfully verified |
| `apiKey` | `?string` | API key associated with the verification |
| `reason` | `?string` | Reason or error message if verification failed |
| `verificationData` | `?ServerSignatureVerificationData` | Verification data returned by Sentinel |

To use your own HTTP client (e.g. Guzzle, Symfony HttpClient) instead of the built-in stream-based one, implement `AltchaOrg\Altcha\Http\HttpClientInterface` and pass it via `httpClient`:

```php
use AltchaOrg\Altcha\Http\HttpClientInterface;
use AltchaOrg\Altcha\Http\HttpResponse;

class MyHttpClient implements HttpClientInterface
{
    public function send(string $url, string $method, array $headers, string $body, float $timeout): HttpResponse
    {
        // ... perform the request with your client of choice ...
        return new HttpResponse($statusCode, $responseBody);
    }
}
```

### `Payload`

Wraps a `Challenge` and `Solution` pair for verification and serialization.

```php
$payload = new Payload($challenge, $solution);

$payload->toArray();   // array
$payload->toJson();    // JSON string
$payload->toBase64();  // base64-encoded JSON
```

## V1 API

The V1 API is available under the `AltchaOrg\Altcha\V1` namespace. It uses simple hash-based challenges (SHA-1, SHA-256, SHA-512) instead of key derivation functions.

## Tests

```sh
vendor/bin/phpunit tests
```

## License

MIT
