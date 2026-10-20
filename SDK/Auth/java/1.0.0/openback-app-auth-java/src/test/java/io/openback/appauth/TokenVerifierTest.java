package io.openback.appauth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenVerifierTest {
    private FakePool pool;
    private TokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        pool = new FakePool();
        verifier = TokenVerifier.builder(pool.issuer + "/").clientIds("uapp_web", "uapp_android").build();
    }

    @AfterEach
    void tearDown() {
        pool.close();
    }

    private String code(Runnable r) {
        return assertThrows(TokenVerificationException.class, r::run).getCode();
    }

    @Test
    void verifiesAValidAccessToken() throws Exception {
        AppUser user = verifier.verify(pool.accessToken("uapp_android"));
        assertEquals("usr_1", user.getId());
        assertEquals("upool_1", user.getPoolId());
        assertEquals("uapp_android", user.getClientId());
        assertEquals("ada@example.com", user.getEmail());
        assertTrue(user.isEmailVerified());
        assertFalse(user.isAnonymous());
        assertEquals("org_1", user.getOrgId());
        assertEquals("ses_1", user.getSessionId());
        assertEquals("pro", user.getAttributes().get("plan"));
        assertTrue(user.hasRole("member"));
        assertFalse(user.hasRole("admin"));
        assertTrue(user.hasPermission("invoices.read"));
        assertFalse(user.hasPermission("invoices.write"));
        assertEquals("pwd", user.getAmr().get(0));
        assertEquals(pool.issuer, user.getClaims().get("iss"));
    }

    @Test
    void wildcardPermissionGrantsEverything() throws Exception {
        Map<String, Object> c = pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 600);
        c.put("permissions", java.util.List.of("*"));
        AppUser user = verifier.verify(pool.sign(pool.header("at+jwt"), c, pool.keys.get(0)));
        assertTrue(user.hasPermission("anything.at.all"));
    }

    @Test
    void acceptsApplicationAtJwtType() throws Exception {
        String token = pool.sign(pool.header("application/AT+JWT"), pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 60), pool.keys.get(0));
        assertEquals("usr_1", verifier.verify(token).getId());
    }

    @Test
    void refusesOtherTypesAndAlgorithms() throws Exception {
        Map<String, Object> claims = pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 600);
        String idTyp = pool.sign(pool.header("JWT"), claims, pool.keys.get(0));
        assertEquals("token_invalid_type", code(() -> verifier.verify(idTyp)));

        Map<String, Object> none = pool.header("at+jwt");
        none.put("alg", "none");
        String unsigned = FakePool.b64json(Json.write(none)) + "." + FakePool.b64json(Json.write(claims)) + ".";
        assertEquals("token_unsupported_alg", code(() -> verifier.verify(unsigned)));

        Map<String, Object> hs = pool.header("at+jwt");
        hs.put("alg", "HS256");
        String hsToken = FakePool.b64json(Json.write(hs)) + "." + FakePool.b64json(Json.write(claims)) + ".c2ln";
        assertEquals("token_unsupported_alg", code(() -> verifier.verify(hsToken)));

        Map<String, Object> rs = pool.header("at+jwt");
        rs.put("alg", "RS256");
        String rsToken = FakePool.b64json(Json.write(rs)) + "." + FakePool.b64json(Json.write(claims)) + ".c2ln";
        assertEquals("token_unsupported_alg", code(() -> verifier.verify(rsToken)));
    }

    @Test
    void refusesMalformedAndMissing() {
        assertEquals("token_missing", code(() -> verifier.verify(null)));
        assertEquals("token_missing", code(() -> verifier.verify(" ")));
        assertEquals("token_malformed", code(() -> verifier.verify("a.b")));
        assertEquals("token_malformed", code(() -> verifier.verify("!!.??.**")));
    }

    @Test
    void refusesABadSignature() throws Exception {
        KeyPair other = FakePool.newKeyPair();
        String forged = pool.sign(pool.header("at+jwt"), pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 600), other);
        assertEquals("token_invalid_signature", code(() -> verifier.verify(forged)));

        String good = pool.accessToken("uapp_web");
        String[] p = good.split("\\.");
        Map<String, Object> claims = pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 600);
        claims.put("roles", java.util.List.of("admin"));
        String tampered = p[0] + "." + FakePool.b64json(Json.write(claims)) + "." + p[2];
        assertEquals("token_invalid_signature", code(() -> verifier.verify(tampered)));
    }

    @Test
    void checksIssuerAudienceAndTimes() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> c = pool.accessClaims("uapp_web", now + 600);
        c.put("iss", pool.issuer + "/other");
        String wrongIss = pool.sign(pool.header("at+jwt"), c, pool.keys.get(0));
        assertEquals("token_invalid_issuer", code(() -> verifier.verify(wrongIss)));

        assertEquals("token_invalid_audience", code(() -> {
            try {
                verifier.verify(pool.accessToken("uapp_someone_else"));
            } catch (TokenVerificationException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }));

        String expired = pool.accessToken("uapp_web", now - 61 - 5);
        assertEquals("token_expired", code(() -> verifier.verify(expired)));
        String withinLeeway = pool.accessToken("uapp_web", now - 30);
        assertEquals("usr_1", verifier.verify(withinLeeway).getId());

        Map<String, Object> nbf = pool.accessClaims("uapp_web", now + 600);
        nbf.put("nbf", now + 300);
        String early = pool.sign(pool.header("at+jwt"), nbf, pool.keys.get(0));
        assertEquals("token_not_yet_valid", code(() -> verifier.verify(early)));

        Map<String, Object> iat = pool.accessClaims("uapp_web", now + 600);
        iat.put("iat", now + 300);
        String future = pool.sign(pool.header("at+jwt"), iat, pool.keys.get(0));
        assertEquals("token_not_yet_valid", code(() -> verifier.verify(future)));
    }

    @Test
    void configurableLeewayAndClock() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String token = pool.accessToken("uapp_web", now + 100);
        TokenVerifier later = TokenVerifier.builder(pool.issuer).clientIds("uapp_web").leeway(Duration.ZERO)
                .clock(Clock.fixed(Instant.ofEpochSecond(now + 101), ZoneOffset.UTC)).build();
        assertEquals("token_expired", code(() -> later.verify(token)));
    }

    @Test
    void cachesTheJwksAndRefetchesOnAnUnknownKidAtMostEvery30Seconds() throws Exception {
        verifier.verify(pool.accessToken("uapp_web"));
        verifier.verify(pool.accessToken("uapp_web"));
        assertEquals(1, pool.rawHits("GET", "/gateway/shop/auth/main/.well-known/jwks.json"));

        // key rotation: a new kid first, refetched once (but not within 30 s of the last fetch)
        pool.addKey("k2");
        String rotated = pool.accessToken("uapp_web");
        assertEquals("token_unknown_key", code(() -> verifier.verify(rotated)));
        assertEquals(1, pool.rawHits("GET", "/gateway/shop/auth/main/.well-known/jwks.json"));

        long[] now = {System.currentTimeMillis() + 31_000};
        TokenVerifier v2 = TokenVerifier.builder(pool.issuer).clientIds("uapp_web")
                .clock(new Clock() {
                    @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
                    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
                    @Override public Instant instant() { return Instant.ofEpochMilli(now[0]); }
                }).build();
        pool.kids.set(0, "k1-old");     // v2 first sees a JWKS without k2...
        String k2token;
        v2.verify(pool.sign(pool.header("at+jwt"), pool.accessClaims("uapp_web", now[0] / 1000 + 600), pool.keys.get(0)));
        int fetches = pool.rawHits("GET", "/gateway/shop/auth/main/.well-known/jwks.json");
        pool.kids.set(0, "k2");         // ...then the pool publishes k2
        k2token = pool.accessToken("uapp_web", now[0] / 1000 + 600);
        String finalK2 = k2token;
        assertEquals("token_unknown_key", code(() -> v2.verify(finalK2)));     // < 30 s since the fetch: no refetch
        assertEquals(fetches, pool.rawHits("GET", "/gateway/shop/auth/main/.well-known/jwks.json"));
        now[0] += 30_001;
        assertEquals("usr_1", v2.verify(k2token).getId());                     // refetched once
        assertEquals(fetches + 1, pool.rawHits("GET", "/gateway/shop/auth/main/.well-known/jwks.json"));
    }

    @Test
    void jwksUnavailable() throws Exception {
        pool.route("GET", "/gateway/shop/auth/main/.well-known/jwks.json", r -> new FakePool.Res(500, "{}"));
        String token = pool.accessToken("uapp_web");
        TokenVerificationException e = assertThrows(TokenVerificationException.class, () -> verifier.verify(token));
        assertEquals("jwks_unavailable", e.getCode());
        assertEquals(503, e.getStatus());
    }

    @Test
    void verifiesIdTokensWithNonce() throws Exception {
        String id = pool.idToken("uapp_web", "n-123");
        assertEquals("usr_1", verifier.verifyIdToken(id, "n-123").get("sub"));
        assertEquals("token_invalid_nonce", code(() -> verifier.verifyIdToken(id, "other")));
        String at = pool.accessToken("uapp_web");
        assertEquals("token_invalid_type", code(() -> verifier.verifyIdToken(at, null)));
    }

    @Test
    void requiresAClientId() {
        assertThrows(IllegalArgumentException.class, () -> TokenVerifier.builder("https://x").build());
    }

    @Test
    void joseDerRoundTrip() {
        byte[] jose = new byte[64];
        jose[0] = (byte) 0x80;          // high bit: needs a 0x00 pad in DER
        jose[31] = 1;
        jose[63] = 7;                   // s with leading zeros
        byte[] der = Es256.joseToDer(jose);
        assertEquals(0x30, der[0]);
        assertArrayEquals(jose, Es256.derToJose(der));
    }

    @Test
    void requirements() throws Exception {
        AppUser user = verifier.verify(pool.accessToken("uapp_web"));
        assertTrue(AppUserRequirements.defaults().isSatisfiedBy(user));
        assertTrue(AppUserRequirements.defaults().requireRoles("admin", "member").isSatisfiedBy(user));
        assertFalse(AppUserRequirements.defaults().requireRoles("admin").isSatisfiedBy(user));
        assertFalse(AppUserRequirements.defaults().requirePermissions("invoices.read", "x").isSatisfiedBy(user));
        assertTrue(AppUserRequirements.defaults().requirePermissions("invoices.read").requireVerifiedEmail(true).isSatisfiedBy(user));

        Map<String, Object> c = pool.accessClaims("uapp_web", System.currentTimeMillis() / 1000 + 600);
        c.put("anon", true);
        c.put("email_verified", false);
        AppUser guest = verifier.verify(pool.sign(pool.header("at+jwt"), c, pool.keys.get(0)));
        assertTrue(guest.isAnonymous());
        assertFalse(AppUserRequirements.defaults().isSatisfiedBy(guest));
        assertTrue(AppUserRequirements.defaults().allowAnonymous(true).isSatisfiedBy(guest));
        assertFalse(AppUserRequirements.defaults().allowAnonymous(true).requireVerifiedEmail(true).isSatisfiedBy(guest));
    }
}
