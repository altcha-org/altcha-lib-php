# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that breaking changes made to match `altcha-lib` (JS) ship in minor releases.

## [2.3.0] - 2026-10-04

### Fixed

- `verifySolution` rejects every challenge with `invalidSignature` when no `hmacSignatureSecret` is configured (`null` or `''`). It used to skip the signature check, so unsigned or tampered challenges verified. `''` now also counts as unset when creating challenges.
- `expiresAt` matches `altcha-lib` (JS): `0` means no expiry, fractional timestamps (e.g. `Date.now() / 1000 + 600`) are accepted and signed as-is, and expiry is checked to the sub-second (no more up to 1 s of grace).
- The canonical JSON used for challenge signatures matches `altcha-lib` (JS) byte-for-byte, so challenges signed by one library verify in the other: JS number formatting, JS key order (array-index keys first, UTF-16 order, objects inside lists left unsorted), empty or list-shaped `data` encoded as an object, U+2028/U+2029 left unescaped.

### Changed

- **BREAKING:** `verifySolution` without a signature secret now always fails.
- **BREAKING:** `ChallengeParameters::$expiresAt` and `CreateChallengeOptions::$expiresAt` are `int|float|null`.
- **BREAKING:** `ChallengeParameters::toArray()['data']` is a `stdClass` when `data` is empty or list-shaped.
- **BREAKING:** `createChallenge()` and `ChallengeParameters::toCanonicalJson()` throw `JsonException` on invalid UTF-8 in `data`, instead of signing an empty string.
- **BREAKING:** challenges with float values in `data` that PHP used to format differently from JS are signed differently; such challenges issued before upgrading fail verification.

## [2.2.0] - 2026-10-01

### Fixed

- Sign the raw derived key bytes in `keySignature` to match `altcha-lib` (JS) ([#25](https://github.com/altcha-org/altcha-lib-php/issues/25)).
- Handling of odd-length `keyPrefix`.

### Changed

- **BREAKING:** challenges with a `keySignature` minted before this release are rejected.

## [2.1.0] - 2026-07-20

### Added

- `VerifySolutionOptions::$payload` accepts a raw base64 string or a decoded array, in addition to a `Payload` object ([#24](https://github.com/altcha-org/altcha-lib-php/issues/24)).
- `Sentinel::verify()` for remote payload verification via the ALTCHA Sentinel API (`POST /v1/verify/signature`), with configurable timeout, retries/backoff, and a pluggable HTTP client.

## [2.0.3] - 2026-07-02

### Fixed

- `verifySolution` rejects a missing challenge signature when a secret is set.

## [2.0.2] - 2026-04-29

### Fixed

- Removed dead `??` fallbacks on non-nullable int properties.
- PHPUnit configuration and CI workflow.

## [2.0.1] - 2026-04-29

### Changed

- Minimum PHP version lowered to 8.1.

## [2.0.0] - 2026-04-07

### Changed

- **BREAKING:** new PoW mechanism v2. See the migration guide [`MIGRATION-v1.md`](MIGRATION-v1.md) and the examples.

## [1.3.3] - 2026-04-02

### Removed

- `ext-json` requirement ([#21](https://github.com/altcha-org/altcha-lib-php/issues/21)).

## [1.3.2] - 2026-02-28

### Changed

- Updated PHPUnit; added `.gitattributes`.

## [1.3.1] - 2025-12-13

### Fixed

- Use `&` instead of `;` as the salt delimiter. Salt parameters stay extractable by previous library versions while still preventing the salt parameter splicing attack.

## [1.3.0] - 2025-12-11

### Security

- Fixed a parameter splicing vulnerability in salt handling that enabled replay attacks.

## [1.2.0] - 2025-11-17

### Added

- `Obfuscator` class ([#16](https://github.com/altcha-org/altcha-lib-php/issues/16)).

## [1.1.2] - 2025-04-06

### Fixed

- Required PHP version in `composer.json` (8.2).

## [1.1.1] - 2025-03-23

### Fixed

- README examples.

## [1.1.0] - 2025-03-16

### Changed

- **BREAKING:** fixed casing of the `maxNumber` parameter in `Challenge`. Compatible only with the ALTCHA widget `>= 1.4.0`; for older widgets use v1.0.0.

## [1.0.0] - 2025-03-16

### Changed

- **BREAKING:** codebase migrated to OOP and PHP 8.1 ([#10](https://github.com/altcha-org/altcha-lib-php/issues/10)). See the README for migration; for older PHP versions use v0.1.4.

## [0.1.4] - 2025-02-28

### Fixed

- Handling of invalid payloads ([#6](https://github.com/altcha-org/altcha-lib-php/issues/6)).

Earlier 0.1.x releases (from 2024-07-26): see the git history.

[2.3.0]: https://github.com/altcha-org/altcha-lib-php/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/altcha-org/altcha-lib-php/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/altcha-org/altcha-lib-php/compare/v2.0.3...v2.1.0
[2.0.3]: https://github.com/altcha-org/altcha-lib-php/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/altcha-org/altcha-lib-php/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/altcha-org/altcha-lib-php/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/altcha-org/altcha-lib-php/compare/v1.3.3...v2.0.0
[1.3.3]: https://github.com/altcha-org/altcha-lib-php/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/altcha-org/altcha-lib-php/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/altcha-org/altcha-lib-php/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/altcha-org/altcha-lib-php/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/altcha-org/altcha-lib-php/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/altcha-org/altcha-lib-php/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/altcha-org/altcha-lib-php/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/altcha-org/altcha-lib-php/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/altcha-org/altcha-lib-php/compare/v0.1.4...v1.0.0
[0.1.4]: https://github.com/altcha-org/altcha-lib-php/compare/v0.1.3...v0.1.4
