package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/** ES256 (ECDSA P-256 + SHA-256) with java.security only: JWK to public key, JOSE R||S signature to DER. */
final class Es256 {
    private static final ECParameterSpec P256 = p256();

    private Es256() { }

    private static ECParameterSpec p256() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is not available in this JVM", e);
        }
    }

    /** The public key of an EC P-256 JWK ({@code kty: EC, crv: P-256, x, y}); null if it is not one. */
    static PublicKey publicKey(JsonNode jwk) {
        if (!"EC".equals(Json.text(jwk, "kty")) || !"P-256".equals(Json.text(jwk, "crv"))) {
            return null;
        }
        String alg = Json.text(jwk, "alg");
        String use = Json.text(jwk, "use");
        if ((alg != null && !"ES256".equals(alg)) || (use != null && !"sig".equals(use))) {
            return null;
        }
        String xs = Json.text(jwk, "x");
        String ys = Json.text(jwk, "y");
        if (xs == null || ys == null) {
            return null;
        }
        try {
            byte[] x = Util.b64urlDecode(xs);
            byte[] y = Util.b64urlDecode(ys);
            if (x.length != 32 || y.length != 32) {
                return null;
            }
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, P256));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }

    /** Verifies a JOSE ES256 signature (64 bytes R||S) of {@code signingInput}. */
    static boolean verify(PublicKey key, byte[] signingInput, byte[] joseSignature) {
        if (joseSignature.length != 64) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(key);
            sig.update(signingInput);
            return sig.verify(joseToDer(joseSignature));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** JOSE R||S (2 x 32 bytes) to an ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }. */
    static byte[] joseToDer(byte[] jose) {
        byte[] r = derInteger(Arrays.copyOfRange(jose, 0, 32));
        byte[] s = derInteger(Arrays.copyOfRange(jose, 32, 64));
        byte[] out = new byte[2 + r.length + s.length];
        out[0] = 0x30;
        out[1] = (byte) (r.length + s.length);          // at most 2 * 35 = 70 < 128: short form
        System.arraycopy(r, 0, out, 2, r.length);
        System.arraycopy(s, 0, out, 2 + r.length, s.length);
        return out;
    }

    private static byte[] derInteger(byte[] unsigned) {
        int start = 0;
        while (start < unsigned.length - 1 && unsigned[start] == 0) {
            start++;
        }
        boolean pad = (unsigned[start] & 0x80) != 0;
        int len = unsigned.length - start + (pad ? 1 : 0);
        byte[] out = new byte[2 + len];
        out[0] = 0x02;
        out[1] = (byte) len;
        System.arraycopy(unsigned, start, out, 2 + (pad ? 1 : 0), unsigned.length - start);
        return out;
    }

    /** A DER ECDSA signature to JOSE R||S (64 bytes). */
    static byte[] derToJose(byte[] der) {
        int offset = 2;
        if ((der[1] & 0x80) != 0) {
            offset = 2 + (der[1] & 0x7f);
        }
        byte[] out = new byte[64];
        int rLen = der[offset + 1];
        copyInt(der, offset + 2, rLen, out, 0);
        int sOff = offset + 2 + rLen;
        int sLen = der[sOff + 1];
        copyInt(der, sOff + 2, sLen, out, 32);
        return out;
    }

    private static void copyInt(byte[] src, int off, int len, byte[] dst, int dstOff) {
        while (len > 32 && src[off] == 0) {
            off++;
            len--;
        }
        System.arraycopy(src, off, dst, dstOff + 32 - len, len);
    }
}
