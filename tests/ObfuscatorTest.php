<?php

namespace AltchaOrg\Altcha\Tests;

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Obfuscator;
use PHPUnit\Framework\TestCase;

class ObfuscatorTest extends TestCase
{
    private Obfuscator $obfuscator;

    protected function setUp(): void
    {
        $altcha = new Altcha();
        $this->obfuscator = new Obfuscator($altcha, new Pbkdf2());
    }

    public function testObfuscateAndDeobfuscateRoundTrip(): void
    {
        $plaintext = 'Hello, World!';

        $obfuscated = $this->obfuscator->obfuscate($plaintext, cost: 100, counterMin: 1, counterMax: 5);

        self::assertNotEmpty($obfuscated);
        self::assertNotEquals($plaintext, $obfuscated);

        $decrypted = $this->obfuscator->deobfuscate($obfuscated);

        self::assertEquals($plaintext, $decrypted);
    }

    public function testObfuscateProducesValidBase64Json(): void
    {
        $obfuscated = $this->obfuscator->obfuscate('test', cost: 100, counterMin: 1, counterMax: 3);

        $json = base64_decode($obfuscated, true);
        self::assertNotFalse($json);

        /** @var array<string, mixed> $data */
        $data = json_decode($json, true);
        self::assertArrayHasKey('parameters', $data);
        self::assertArrayHasKey('cipher', $data);
        self::assertArrayHasKey('iv', $data['cipher']); // @phpstan-ignore-line
        self::assertArrayHasKey('data', $data['cipher']);
    }

    public function testObfuscateKeyPrefixIsTruncated(): void
    {
        $obfuscated = $this->obfuscator->obfuscate('test', cost: 100, counterMin: 1, counterMax: 3);

        $json = base64_decode($obfuscated, true);
        self::assertNotFalse($json);

        /** @var array{parameters: array{keyPrefix: string, keyLength: int}} $data */
        $data = json_decode($json, true);

        // keyPrefix should be truncated to keyLength hex chars (half the full key)
        self::assertEquals($data['parameters']['keyLength'], \strlen($data['parameters']['keyPrefix']));
    }

    public function testDeobfuscateInvalidBase64(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to parse obfuscated data.');

        $this->obfuscator->deobfuscate('not-valid-base64!!!');
    }

    public function testDeobfuscateInvalidJson(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid obfuscated data format.');

        $this->obfuscator->deobfuscate(base64_encode('not json'));
    }

    public function testDeobfuscateMissingCipher(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid obfuscated data format.');

        $this->obfuscator->deobfuscate(base64_encode(json_encode(['parameters' => []]))); // @phpstan-ignore-line
    }

    public function testObfuscateEmptyString(): void
    {
        $obfuscated = $this->obfuscator->obfuscate('', cost: 100, counterMin: 1, counterMax: 3);
        $decrypted = $this->obfuscator->deobfuscate($obfuscated);

        self::assertEquals('', $decrypted);
    }

    public function testObfuscateUnicodeString(): void
    {
        $plaintext = "Hello 世界! 🌍 Ñoño";

        $obfuscated = $this->obfuscator->obfuscate($plaintext, cost: 100, counterMin: 1, counterMax: 3);
        $decrypted = $this->obfuscator->deobfuscate($obfuscated);

        self::assertEquals($plaintext, $decrypted);
    }

    public function testObfuscateProducesDifferentOutputEachTime(): void
    {
        $plaintext = 'same input';

        $obfuscated1 = $this->obfuscator->obfuscate($plaintext, cost: 100, counterMin: 1, counterMax: 50);
        $obfuscated2 = $this->obfuscator->obfuscate($plaintext, cost: 100, counterMin: 1, counterMax: 50);

        // Different nonce/salt/counter/IV means different output
        self::assertNotEquals($obfuscated1, $obfuscated2);
    }
}
