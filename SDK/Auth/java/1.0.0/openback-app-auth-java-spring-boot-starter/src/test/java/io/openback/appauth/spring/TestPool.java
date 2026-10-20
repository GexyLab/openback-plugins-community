package io.openback.appauth.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A fake pool for the starter's tests: JWKS on 127.0.0.1 and ES256 tokens signed with a key generated per run. */
final class TestPool {
    static final TestPool INSTANCE = new TestPool();

    final KeyPair key;
    final String issuer;
    private final ObjectMapper mapper = new ObjectMapper();

    private TestPool() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            key = g.generateKeyPair();
            HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            String path = "/gateway/shop/auth/main";
            server.createContext(path + "/.well-known/jwks.json", ex -> {
                byte[] body = jwks().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type", "application/json");
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(body);
                }
            });
            server.setExecutor(null);
            server.start();
            issuer = "http://127.0.0.1:" + server.getAddress().getPort() + path;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static byte[] fixed(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    private String jwks() {
        ECPublicKey pub = (ECPublicKey) key.getPublic();
        return "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"use\":\"sig\",\"kid\":\"k1\",\"x\":\""
                + b64(fixed(pub.getW().getAffineX())) + "\",\"y\":\"" + b64(fixed(pub.getW().getAffineY())) + "\"}]}";
    }

    Map<String, Object> claims(String clientId, List<String> roles, List<String> permissions) {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", issuer);
        c.put("sub", "usr_1");
        c.put("aud", clientId);
        c.put("exp", now + 600);
        c.put("iat", now);
        c.put("sid", "ses_1");
        c.put("pool", "upool_1");
        c.put("org_id", "org_1");
        c.put("roles", roles);
        c.put("permissions", permissions);
        c.put("email", "ada@example.com");
        c.put("email_verified", true);
        return c;
    }

    String token(Map<String, Object> claims) {
        try {
            String input = b64(mapper.writeValueAsBytes(Map.of("alg", "ES256", "typ", "at+jwt", "kid", "k1")))
                    + "." + b64(mapper.writeValueAsBytes(claims));
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(key.getPrivate());
            s.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + b64(derToJose(s.sign()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String token(List<String> roles, List<String> permissions) {
        return token(claims("uapp_web", roles, permissions));
    }

    private static byte[] derToJose(byte[] der) {
        int offset = (der[1] & 0x80) != 0 ? 2 + (der[1] & 0x7f) : 2;
        byte[] out = new byte[64];
        int rLen = der[offset + 1];
        copy(der, offset + 2, rLen, out, 0);
        int sOff = offset + 2 + rLen;
        copy(der, sOff + 2, der[sOff + 1], out, 32);
        return out;
    }

    private static void copy(byte[] src, int off, int len, byte[] dst, int dstOff) {
        while (len > 32 && src[off] == 0) {
            off++;
            len--;
        }
        System.arraycopy(src, off, dst, dstOff + 32 - len, len);
    }
}
