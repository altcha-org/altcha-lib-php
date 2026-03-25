## Migrating from V1 to V2

### Constructor

```php
// V1
$altcha = new \AltchaOrg\Altcha\V1\Altcha('secret');

// V2
$altcha = new \AltchaOrg\Altcha\Altcha(
    hmacSignatureSecret: 'secret',
    hmacKeySignatureSecret: 'key-secret', // optional, enables fast verification
);
```

### Algorithm

V1 uses a simple hash `Algorithm` enum. V2 uses pluggable key derivation algorithms implementing `DeriveKeyInterface`.

```php
// V1
use AltchaOrg\Altcha\V1\Hasher\Algorithm;
Algorithm::SHA256;

// V2
use AltchaOrg\Altcha\Algorithm\Pbkdf2;
$pbkdf2 = new Pbkdf2(); // PBKDF2/SHA-256
```

### Creating challenges

```php
// V1
use AltchaOrg\Altcha\V1\ChallengeOptions;

$challenge = $altcha->createChallenge(new ChallengeOptions(
    algorithm: Algorithm::SHA256,
    maxNumber: 100000,
    expires: new \DateTimeImmutable('+2 minutes'),
));

// V2
use AltchaOrg\Altcha\CreateChallengeOptions;

$challenge = $altcha->createChallenge(new CreateChallengeOptions(
    algorithm: $pbkdf2,
    cost: 5000,
    counter: random_int(5000, 10000),
    expiresAt: new \DateTimeImmutable('+2 minutes'), // or unix timestamp
));
```

V2 challenges use `ChallengeParameters` (accessed via `$challenge->parameters`) instead of flat properties. Key differences:

| V1 | V2 |
|---|---|
| `$challenge->algorithm` | `$challenge->parameters->algorithm` |
| `$challenge->challenge` | n/a (prefix matching replaces challenge hash) |
| `$challenge->maxNumber` | n/a (replaced by timeout-based solving) |
| `$challenge->salt` | `$challenge->parameters->salt` |
| `$challenge->signature` | `$challenge->signature` |

### Solving challenges

```php
// V1
$solution = $altcha->solveChallenge(
    $challenge->challenge,
    $challenge->salt,
    Algorithm::SHA256,
    $challenge->maxNumber,
);
// $solution->number, $solution->took

// V2
use AltchaOrg\Altcha\SolveChallengeOptions;

$solution = $altcha->solveChallenge(new SolveChallengeOptions(
    challenge: $challenge,
    algorithm: $pbkdf2,
    timeout: 30.0, // seconds (default)
));
// $solution->counter, $solution->derivedKey, $solution->time
```

| V1 | V2 |
|---|---|
| `$solution->number` | `$solution->counter` |
| `$solution->took` | `$solution->time` |
| n/a | `$solution->derivedKey` |
| `maxNumber` (iteration limit) | `timeout` (time limit in seconds) |

### Verifying solutions

```php
// V1 - returns bool
$payload = base64_encode(json_encode([...]));
$isValid = $altcha->verifySolution($payload);

// V2 - returns VerifySolutionResult with detailed diagnostics
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\VerifySolutionOptions;

$payload = new Payload($challenge, $solution);
$result = $altcha->verifySolution(new VerifySolutionOptions(
    payload: $payload,
    algorithm: $pbkdf2,
));

$result->verified;          // bool
$result->expired;           // bool
$result->invalidSignature;  // ?bool
$result->invalidSolution;   // ?bool
$result->time;              // float (seconds)
```

### Server signature verification

Moved from an instance method to a static method on a dedicated class. The HMAC key must now be passed explicitly.

```php
// V1
$result = $altcha->verifyServerSignature($payload);
$result->verified;
$result->data->classification;  // fixed properties

// V2
use AltchaOrg\Altcha\ServerSignature;

$result = ServerSignature::verifyServerSignature($payload, 'server-secret');
$result->verified;
$result->expired;               // new
$result->invalidSignature;      // new
$result->invalidSolution;       // new
$result->verificationData->classification;  // generic dynamic properties
$result->verificationData['classification'];  // array access also works
```

V2 `ServerSignatureVerificationData` is a generic container instead of a fixed-property class. Any key from the verification data is accessible via property or array syntax.

### Fields hash verification

Also moved to a static method:

```php
// V1
$isValid = $altcha->verifyFieldsHash($formData, $fields, $fieldsHash, Algorithm::SHA256);

// V2
$isValid = ServerSignature::verifyFieldsHash($formData, $fields, $fieldsHash);
```