<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests;

use OpenBack\AppAuth\Internal\Base64Url;
use OpenBack\AppAuth\Internal\Ecdsa;
use OpenBack\AppAuth\Tests\Support\TestKeys;
use PHPUnit\Framework\TestCase;

final class EcdsaTest extends TestCase
{
    public function testJwkToPemGivesTheSamePublicKey(): void
    {
        $keys = new TestKeys();
        $pem = Ecdsa::jwkToPem($keys->jwk);
        $public = openssl_pkey_get_public($pem);
        self::assertNotFalse($public);
        $expected = openssl_pkey_get_details($keys->private)['key'];
        self::assertSame(trim($expected), trim(openssl_pkey_get_details($public)['key']));
    }

    public function testSignaturesRoundTripAndVerify(): void
    {
        $keys = new TestKeys();
        $pem = Ecdsa::jwkToPem($keys->jwk);
        // Many signatures: some r/s have a high bit (DER adds 0x00), some start with zero bytes (stripped).
        for ($i = 0; $i < 200; $i++) {
            $data = 'message ' . $i;
            self::assertTrue(openssl_sign($data, $der, $keys->private, OPENSSL_ALGO_SHA256));
            $jose = Ecdsa::derToJose($der);
            self::assertSame(64, strlen($jose));
            $back = Ecdsa::joseToDer($jose);
            self::assertSame(bin2hex($der), bin2hex($back), 'canonical DER round trip');
            self::assertSame(1, openssl_verify($data, $back, $pem, OPENSSL_ALGO_SHA256));
            self::assertSame(0, openssl_verify($data . 'x', $back, $pem, OPENSSL_ALGO_SHA256));
        }
    }

    public function testJoseToDerHandlesLeadingZerosAndHighBits(): void
    {
        $r = str_repeat("\x00", 3) . str_repeat("\x7f", 29);
        $s = "\x80" . str_repeat("\x01", 31);
        $der = Ecdsa::joseToDer($r . $s);
        self::assertSame('30' . '42' . '021d' . str_repeat('7f', 29) . '0221' . '0080' . str_repeat('01', 31), bin2hex($der));
        self::assertSame(bin2hex($r . $s), bin2hex(Ecdsa::derToJose($der)));
    }

    public function testRejectsBadInputs(): void
    {
        foreach ([
            static fn () => Ecdsa::joseToDer(str_repeat('a', 63)),
            static fn () => Ecdsa::derToJose("\x31\x00"),
            static fn () => Ecdsa::jwkToPem(['kty' => 'RSA', 'n' => 'x', 'e' => 'AQAB']),
            static fn () => Ecdsa::jwkToPem(['kty' => 'EC', 'crv' => 'P-384', 'x' => 'AA', 'y' => 'AA']),
            static fn () => Ecdsa::jwkToPem(['kty' => 'EC', 'crv' => 'P-256', 'x' => Base64Url::encode('short'), 'y' => Base64Url::encode('short')]),
        ] as $i => $bad) {
            try {
                $bad();
                self::fail("case $i accepted");
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function testInvalidCurvePointIsNotAccepted(): void
    {
        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => Base64Url::encode(str_repeat("\x01", 32)), 'y' => Base64Url::encode(str_repeat("\x02", 32))];
        $pem = Ecdsa::jwkToPem($jwk);
        self::assertFalse(@openssl_pkey_get_public($pem));
        while (openssl_error_string() !== false) {
        }
    }

    public function testBase64Url(): void
    {
        $bytes = random_bytes(100);
        self::assertSame($bytes, Base64Url::decode(Base64Url::encode($bytes)));
        $this->expectException(\InvalidArgumentException::class);
        Base64Url::decode('ab+c');
    }
}
