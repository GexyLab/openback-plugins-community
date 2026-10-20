package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Verifies the pool's access tokens in your backend, locally (no call to OpenBack): ES256 signature with the pool's JWKS
 * ({@code <issuer>/.well-known/jwks.json}, cached 10 minutes, fetched again on an unknown {@code kid} at most once every
 * 30 seconds), {@code typ at+jwt}, {@code iss}, {@code aud} (one of your client IDs), {@code exp}/{@code nbf}/{@code iat}
 * with a leeway (default 60 s). Only ES256 is accepted ({@code none}, HS*, RS* are refused). Thread-safe: build one and
 * share it.
 *
 * <pre>{@code
 * TokenVerifier verifier = TokenVerifier.builder("https://api.example.com/gateway/shop/auth/main")
 *         .clientIds("uapp_web", "uapp_android").build();
 * AppUser user = verifier.verify(bearerToken);      // throws TokenVerificationException
 * }</pre>
 *
 * Access tokens cannot be revoked before they expire: keep them short-lived (the pool's default is 15 minutes).
 */
public final class TokenVerifier {
    private static final long UNKNOWN_KID_REFETCH_MS = 30_000L;

    private final String issuer;
    private final Set<String> clientIds;
    private final String jwksUri;
    private final long leewaySeconds;
    private final long cacheTtlMs;
    private final HttpClient http;
    private final Duration timeout;
    private final Clock clock;
    private final Object fetchLock = new Object();
    private volatile Map<String, PublicKey> keys = Collections.emptyMap();
    private volatile long fetchedAt = Long.MIN_VALUE / 2;

    private TokenVerifier(Builder b) {
        this.issuer = Util.normalizeIssuer(b.issuer);
        if (b.clientIds.isEmpty()) {
            throw new IllegalArgumentException("TokenVerifier: at least one client ID is required");
        }
        this.clientIds = Collections.unmodifiableSet(new LinkedHashSet<>(b.clientIds));
        this.jwksUri = b.jwksUri != null ? b.jwksUri : issuer + "/.well-known/jwks.json";
        this.leewaySeconds = b.leeway.getSeconds();
        this.cacheTtlMs = b.cacheTtl.toMillis();
        this.http = b.httpClient != null ? b.httpClient : Http.defaultClient();
        this.timeout = b.timeout;
        this.clock = b.clock != null ? b.clock : Clock.systemUTC();
    }

    public static Builder builder(String issuer) {
        return new Builder(issuer);
    }

    public String getIssuer() {
        return issuer;
    }

    public Set<String> getClientIds() {
        return clientIds;
    }

    /**
     * Verifies an access token (without the "Bearer " prefix).
     *
     * @throws TokenVerificationException if the token is not valid (status 401) or the keys are unavailable (503)
     */
    public AppUser verify(String token) {
        Map<String, Object> claims = verifyJwt(token, true);
        return new AppUser(claims, (String) audienceMatch(claims.get("aud")));
    }

    /**
     * Verifies an ID token ({@code typ JWT}) of a hosted sign-in and its {@code nonce} (when {@code expectedNonce} is not
     * null). Returns its claims.
     */
    public Map<String, Object> verifyIdToken(String idToken, String expectedNonce) {
        Map<String, Object> claims = verifyJwt(idToken, false);
        if (expectedNonce != null) {
            Object nonce = claims.get("nonce");
            if (!(nonce instanceof String) || !Util.constantTimeEquals(expectedNonce, (String) nonce)) {
                throw new TokenVerificationException("token_invalid_nonce", "ID token nonce mismatch");
            }
        }
        return claims;
    }

    /** Drops the cached keys (the next verification fetches them). */
    public void clearCache() {
        synchronized (fetchLock) {
            keys = Collections.emptyMap();
            fetchedAt = Long.MIN_VALUE / 2;
        }
    }

    private Map<String, Object> verifyJwt(String token, boolean access) {
        if (token == null || token.isBlank()) {
            throw new TokenVerificationException("token_missing", "No token");
        }
        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 3) {
            throw new TokenVerificationException("token_malformed", "Not a JWS compact token");
        }
        JsonNode header;
        JsonNode payload;
        byte[] signature;
        try {
            header = Json.parse(new String(Util.b64urlDecode(parts[0]), StandardCharsets.UTF_8));
            payload = Json.parse(new String(Util.b64urlDecode(parts[1]), StandardCharsets.UTF_8));
            signature = Util.b64urlDecode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenVerificationException("token_malformed", "Invalid base64url", e);
        }
        if (!header.isObject() || !payload.isObject()) {
            throw new TokenVerificationException("token_malformed", "Invalid JSON");
        }
        if (!"ES256".equals(Json.text(header, "alg"))) {
            throw new TokenVerificationException("token_unsupported_alg", "Only ES256 is accepted");
        }
        if (header.has("crit")) {
            throw new TokenVerificationException("token_malformed", "Unsupported critical header");
        }
        String typ = Json.text(header, "typ");
        String t = typ == null ? null : typ.toLowerCase(Locale.ROOT);
        if (access) {
            if (!"at+jwt".equals(t) && !"application/at+jwt".equals(t)) {
                throw new TokenVerificationException("token_invalid_type", "Not an access token (typ at+jwt)");
            }
        } else if (t != null && !"jwt".equals(t) && !"application/jwt".equals(t)) {
            throw new TokenVerificationException("token_invalid_type", "Not an ID token (typ JWT)");
        }
        PublicKey key = key(Json.text(header, "kid"));
        byte[] input = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!Es256.verify(key, input, signature)) {
            throw new TokenVerificationException("token_invalid_signature", "Invalid signature");
        }
        Map<String, Object> claims = Json.toMap(payload);
        if (!issuer.equals(claims.get("iss"))) {
            throw new TokenVerificationException("token_invalid_issuer", "Unexpected issuer");
        }
        if (audienceMatch(claims.get("aud")) == null) {
            throw new TokenVerificationException("token_invalid_audience", "Token of another app");
        }
        long now = clock.millis() / 1000L;
        Long exp = number(claims.get("exp"));
        if (exp == null) {
            throw new TokenVerificationException("token_malformed", "No exp claim");
        }
        if (now > exp + leewaySeconds) {
            throw new TokenVerificationException("token_expired", "Token expired");
        }
        Long nbf = number(claims.get("nbf"));
        if (nbf != null && now + leewaySeconds < nbf) {
            throw new TokenVerificationException("token_not_yet_valid", "Token not valid yet");
        }
        Long iat = number(claims.get("iat"));
        if (iat != null && iat > now + leewaySeconds) {
            throw new TokenVerificationException("token_not_yet_valid", "Token issued in the future");
        }
        return claims;
    }

    private Object audienceMatch(Object aud) {
        if (aud instanceof String) {
            return clientIds.contains(aud) ? aud : null;
        }
        if (aud instanceof Collection) {
            for (Object a : (Collection<?>) aud) {
                if (a instanceof String && clientIds.contains(a)) {
                    return a;
                }
            }
        }
        return null;
    }

    private static Long number(Object v) {
        return v instanceof Number ? ((Number) v).longValue() : null;
    }

    private PublicKey key(String kid) {
        long now = clock.millis();
        Map<String, PublicKey> current = keys;
        if (now - fetchedAt > cacheTtlMs) {
            current = fetch(false);
        }
        PublicKey key = select(current, kid);
        if (key == null) {
            key = select(fetch(true), kid);    // a rotated key: refetch, at most once every 30 s
        }
        if (key == null) {
            throw new TokenVerificationException("token_unknown_key", "Unknown signing key");
        }
        return key;
    }

    private static PublicKey select(Map<String, PublicKey> keys, String kid) {
        if (kid != null) {
            return keys.get(kid);
        }
        return keys.size() == 1 ? keys.values().iterator().next() : null;
    }

    private Map<String, PublicKey> fetch(boolean unknownKid) {
        synchronized (fetchLock) {
            long now = clock.millis();
            if (unknownKid ? now - fetchedAt < UNKNOWN_KID_REFETCH_MS : now - fetchedAt <= cacheTtlMs) {
                return keys;                           // fetched meanwhile, or too soon
            }
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(jwksUri)).timeout(timeout)
                        .header("Accept", "application/json").GET().build();
                HttpResponse<String> res = Http.send(http, req);
                JsonNode body = Json.parse(res.body());
                if (res.statusCode() != 200 || !body.path("keys").isArray()) {
                    throw new TokenVerificationException("jwks_unavailable", "JWKS answered HTTP " + res.statusCode());
                }
                Map<String, PublicKey> next = new HashMap<>();
                for (JsonNode jwk : body.get("keys")) {
                    PublicKey k = Es256.publicKey(jwk);
                    String kid = Json.text(jwk, "kid");
                    if (k != null) {
                        next.put(kid != null ? kid : "", k);
                    }
                }
                keys = Collections.unmodifiableMap(next);
                fetchedAt = now;
                return keys;
            } catch (AppAuthException e) {
                if (!keys.isEmpty()) {
                    fetchedAt = now - cacheTtlMs + UNKNOWN_KID_REFETCH_MS;   // keep the stale keys, retry in 30 s
                    return keys;
                }
                throw e instanceof TokenVerificationException ? e
                        : new TokenVerificationException("jwks_unavailable", "JWKS unavailable", e);
            }
        }
    }

    /** Options of {@link TokenVerifier}. */
    public static final class Builder {
        private final String issuer;
        private final Set<String> clientIds = new LinkedHashSet<>();
        private String jwksUri;
        private Duration leeway = Duration.ofSeconds(60);
        private Duration cacheTtl = Duration.ofMinutes(10);
        private HttpClient httpClient;
        private Duration timeout = Duration.ofSeconds(10);
        private Clock clock;

        private Builder(String issuer) {
            this.issuer = issuer;
        }

        /** The accepted audiences: the client IDs of your apps ({@code uapp_...}). Required. */
        public Builder clientIds(String... value) {
            clientIds.addAll(new ArrayList<>(Arrays.asList(value)));
            return this;
        }

        public Builder clientIds(Collection<String> value) {
            clientIds.addAll(value);
            return this;
        }

        /** Default {@code <issuer>/.well-known/jwks.json} (discovery's {@code jwks_uri}). */
        public Builder jwksUri(String value) {
            this.jwksUri = value;
            return this;
        }

        /** Clock leeway for exp/nbf/iat (default 60 s). */
        public Builder leeway(Duration value) {
            this.leeway = value;
            return this;
        }

        /** How long the JWKS is cached (default 10 minutes). */
        public Builder jwksCacheTtl(Duration value) {
            this.cacheTtl = value;
            return this;
        }

        public Builder httpClient(HttpClient value) {
            this.httpClient = value;
            return this;
        }

        /** Timeout of the JWKS request (default 10 s). */
        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        public Builder clock(Clock value) {
            this.clock = value;
            return this;
        }

        public TokenVerifier build() {
            return new TokenVerifier(this);
        }
    }
}
