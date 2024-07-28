# ALTCHA PHP Library

The ALTCHA PHP Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges, specifically tailored for PHP applications.

## Compatibility

This library is compatible with:

- PHP 7.4+
- All major platforms (Linux, Windows, macOS)

## Example

- [Demo server](https://github.com/altcha-org/altcha-starter-php)

## Installation

To install the ALTCHA PHP Library, use the following command:

```sh
composer require altcha-org/altcha
```

## Usage

Here’s a basic example of how to use the ALTCHA PHP Library:

```php
<?php

require 'vendor/autoload.php';

use AltchaOrg\Altcha\ChallengeOptions;
use AltchaOrg\Altcha\Altcha;

$hmacKey = 'secret hmac key';

// Create a new challenge
$options = new ChallengeOptions([
    'hmacKey'   => $hmacKey,
    'maxNumber' => 50000, // the maximum random number
]);

$challenge = Altcha::createChallenge($options);
echo "Challenge created: " . json_encode($challenge) . "\n";

// Example payload to verify
$payload = [
    'algorithm' => $challenge['algorithm'],
    'challenge' => $challenge['challenge'],
    'number'    => 12345, // Example number
    'salt'      => $challenge['salt'],
    'signature' => $challenge['signature'],
];

// Verify the solution
$ok = Altcha::verifySolution($payload, $hmacKey, true);

if ($ok) {
    echo "Solution verified!\n";
} else {
    echo "Invalid solution.\n";
}
```

## API

### `Altcha::createChallenge(array $options): array`

Creates a new challenge for ALTCHA.

**Parameters:**

- `options array`:
  - `algorithm string`: Hashing algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default: `SHA-256`).
  - `maxNumber int`: Maximum number for the random number generator (default: 1,000,000).
  - `saltLength int`: Length of the random salt (default: 12 bytes).
  - `hmacKey string`: Required HMAC key.
  - `salt string`: Optional salt string. If not provided, a random salt will be generated.
  - `number int`: Optional specific number to use. If not provided, a random number will be generated.
  - `expires \DateTime`: Optional expiration time for the challenge.
  - `params array`: Optional URL-encoded query parameters.

**Returns:** `array`

### `Altcha::verifySolution(array $payload, string $hmacKey, bool $checkExpires): bool`

Verifies an ALTCHA solution.

**Parameters:**

- `payload array`: The solution payload to verify.
- `hmacKey string`: The HMAC key used for verification.
- `checkExpires bool`: Whether to check if the challenge has expired.

**Returns:** `bool`

### `Altcha::extractParams(array $payload): array`

Extracts URL parameters from the payload's salt.

**Parameters:**

- `payload array`: The payload containing the salt.

**Returns:** `array`

### `Altcha::verifyFieldsHash(array $formData, array $fields, string $fieldsHash, string $algorithm): bool`

Verifies the hash of form fields.

**Parameters:**

- `formData array`: The form data to hash.
- `fields array`: The fields to include in the hash.
- `fieldsHash string`: The expected hash value.
- `algorithm string`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).

**Returns:** `bool`

### `Altcha::verifyServerSignature($payload, string $hmacKey): array`

Verifies the server signature.

**Parameters:**

- `payload mixed`: The payload to verify (string or `ServerSignaturePayload` array).
- `hmacKey string`: The HMAC key used for verification.

**Returns:** `array`

### `Altcha::solveChallenge(string $challenge, string $salt, string $algorithm, int $max, int $start, $stopChan = null): array`

Finds a solution to the given challenge.

**Parameters:**

- `challenge string`: The challenge hash.
- `salt string`: The challenge salt.
- `algorithm string`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).
- `max int`: Maximum number to iterate to.
- `start int`: Starting number.

**Returns:** `array`


## Tests

```sh
vendor/bin/phpunit --bootstrap src/Altcha.php tests/AltchaTest.php
```

## License

MIT