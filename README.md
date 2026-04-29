# ALTCHA PHP Library

A lightweight PHP library for creating and verifying [ALTCHA](https://altcha.org) challenges using key derivation functions (PBKDF2, Argon2id, Scrypt).

## Compatibility

- PHP 8.1+

## Migrating from V1 to V2

- [`MIGRATION-v1.md`](/MIGRATION-v1.md)

## Example

- [Basic Server](/examples/server.php)
- [Server Signature](/examples/server_verify.php)

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
| `payload` | `Payload` | required | Challenge + solution pair |

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
