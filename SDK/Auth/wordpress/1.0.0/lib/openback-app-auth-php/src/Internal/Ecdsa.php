<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk\Internal;

/**
 * @internal ES256 with ext-openssl only:
 *  - a JWK (kty EC, crv P-256) becomes a PEM SubjectPublicKeyInfo for openssl_verify();
 *  - a JOSE signature (raw R || S, 64 bytes) becomes the DER SEQUENCE { INTEGER r, INTEGER s } that OpenSSL expects,
 *    and back (DER -> JOSE, used to sign test tokens).
 */
final class Ecdsa
{
    /** DER prefix of a P-256 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (66 bytes) }. */
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    private const PART = 32;

    /**
     * @param array<string, mixed> $jwk
     * @throws \InvalidArgumentException when the key is not an EC P-256 public key
     */
    public static function jwkToPem(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') {
            throw new \InvalidArgumentException('not an EC P-256 key');
        }
        if (!is_string($jwk['x'] ?? null) || !is_string($jwk['y'] ?? null)) {
            throw new \InvalidArgumentException('EC key without coordinates');
        }
        $x = Base64Url::decode($jwk['x']);
        $y = Base64Url::decode($jwk['y']);
        if (strlen($x) !== self::PART || strlen($y) !== self::PART) {
            throw new \InvalidArgumentException('EC P-256 coordinates must be 32 bytes');
        }
        $der = hex2bin(self::P256_SPKI_PREFIX) . "\x04" . $x . $y;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** @throws \InvalidArgumentException when the signature is not 64 bytes */
    public static function joseToDer(string $signature): string
    {
        if (strlen($signature) !== 2 * self::PART) {
            throw new \InvalidArgumentException('ES256 signature must be 64 bytes');
        }
        $sequence = self::derInteger(substr($signature, 0, self::PART)) . self::derInteger(substr($signature, self::PART));
        return "\x30" . chr(strlen($sequence)) . $sequence;      // at most 70 bytes: short length form
    }

    /** @throws \InvalidArgumentException on a malformed DER signature */
    public static function derToJose(string $der): string
    {
        $offset = 0;
        if (self::byte($der, $offset++) !== 0x30) {
            throw new \InvalidArgumentException('DER signature: SEQUENCE expected');
        }
        $length = self::byte($der, $offset++);
        if ($length & 0x80) {
            if ($length !== 0x81) {
                throw new \InvalidArgumentException('DER signature: unexpected length');
            }
            $length = self::byte($der, $offset++);
        }
        if ($offset + $length !== strlen($der)) {
            throw new \InvalidArgumentException('DER signature: bad length');
        }
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            if (self::byte($der, $offset++) !== 0x02) {
                throw new \InvalidArgumentException('DER signature: INTEGER expected');
            }
            $intLength = self::byte($der, $offset++);
            $int = substr($der, $offset, $intLength);
            if (strlen($int) !== $intLength) {
                throw new \InvalidArgumentException('DER signature: truncated');
            }
            $offset += $intLength;
            $int = ltrim($int, "\x00");
            if (strlen($int) > self::PART) {
                throw new \InvalidArgumentException('DER signature: integer too large');
            }
            $out .= str_pad($int, self::PART, "\x00", STR_PAD_LEFT);
        }
        return $out;
    }

    private static function derInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;              // keep it positive
        }
        return "\x02" . chr(strlen($bytes)) . $bytes;
    }

    private static function byte(string $data, int $offset): int
    {
        if ($offset >= strlen($data)) {
            throw new \InvalidArgumentException('DER signature: truncated');
        }
        return ord($data[$offset]);
    }
}
