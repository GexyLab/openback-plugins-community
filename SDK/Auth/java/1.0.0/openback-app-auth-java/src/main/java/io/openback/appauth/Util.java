package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;

/** Small helpers: base64url, CSPRNG strings, PKCE, query strings, unverified JWT decoding. */
final class Util {
    private static final SecureRandom RANDOM = new SecureRandom();

    private Util() { }

    static String normalizeIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        String out = issuer.trim();
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }

    static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] b64urlDecode(String text) {
        return Base64.getUrlDecoder().decode(text);
    }

    /** {@code bytes} random bytes from the platform CSPRNG, base64url-encoded. */
    static String randomString(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return b64url(buf);
    }

    /** A PKCE code verifier: 48 random bytes, 64 base64url characters (RFC 7636: 43..128). */
    static String codeVerifier() {
        return randomString(48);
    }

    /** The S256 code challenge of a verifier. */
    static String codeChallenge(String verifier) {
        return b64url(sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Constant-time comparison of two strings (null-safe: null never equals anything). */
    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static String query(Map<String, String> params) {
        StringJoiner out = new StringJoiner("&");
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (e.getValue() != null) {
                out.add(encode(e.getKey()) + "=" + encode(e.getValue()));
            }
        }
        return out.toString();
    }

    /** application/x-www-form-urlencoded body. */
    static String form(Map<String, String> params) {
        StringJoiner out = new StringJoiner("&");
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (e.getValue() != null) {
                out.add(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            }
        }
        return out.toString();
    }

    /** The query parameters of a URL (first value of each name). */
    static Map<String, String> queryParams(String url) {
        Map<String, String> out = new LinkedHashMap<>();
        String raw;
        try {
            raw = URI.create(url.trim()).getRawQuery();
        } catch (IllegalArgumentException e) {
            int q = url.indexOf('?');
            raw = q >= 0 ? url.substring(q + 1) : null;
        }
        if (raw == null || raw.isEmpty()) {
            return out;
        }
        int hash = raw.indexOf('#');
        if (hash >= 0) {
            raw = raw.substring(0, hash);
        }
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String k = URLDecoder.decode(eq >= 0 ? pair.substring(0, eq) : pair, StandardCharsets.UTF_8);
            String v = eq >= 0 ? URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8) : "";
            out.putIfAbsent(k, v);
        }
        return out;
    }

    /** The payload of a JWT, NOT verified (for display and expiry only), or null if it is not a JWT. */
    static JsonNode decodeJwtPayload(String token) {
        if (token == null) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return null;
        }
        try {
            JsonNode node = Json.parse(new String(b64urlDecode(parts[1]), StandardCharsets.UTF_8));
            return node.isObject() ? node : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Basic client authentication header (RFC 6749 2.3.1: id and secret form-url-encoded first). */
    static String basicAuth(String clientId, String clientSecret) {
        String raw = encode(clientId) + ":" + encode(clientSecret);
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }
}
