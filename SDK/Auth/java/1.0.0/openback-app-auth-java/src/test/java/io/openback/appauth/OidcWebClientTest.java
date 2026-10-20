package io.openback.appauth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcWebClientTest {
    private static final String CLIENT = "uapp_web";
    private FakePool pool;
    private OidcWebClient oidc;

    @BeforeEach
    void setUp() throws Exception {
        pool = new FakePool();
        oidc = OidcWebClient.builder(pool.issuer, CLIENT, "top secret", "https://app.example.com/callback").build();
    }

    @AfterEach
    void tearDown() {
        assertTrue(pool.failures.isEmpty(), () -> "fake pool assertion failed: " + pool.failures);
        pool.close();
    }

    @Test
    void fullCodeFlowWithBasicAuthAndVerifiedIdToken() throws Exception {
        AuthorizationRequest tx = oidc.authorizationUrl(new AuthorizationOptions().provider("uprov_ms"));
        Map<String, String> q = Util.queryParams(tx.getUrl());
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals("uprov_ms", q.get("provider"));
        AuthorizationRequest restored = AuthorizationRequest.fromJson(tx.toJson());

        String idToken = pool.idToken(CLIENT, tx.getNonce());
        String at = pool.accessToken(CLIENT);
        pool.route("POST", "/gateway/shop/auth/main/token", r -> {
            assertEquals(Util.basicAuth(CLIENT, "top secret"), r.header("Authorization"));
            assertTrue(r.header("Authorization").length() > 6);
            assertEquals(tx.getCodeVerifier(), r.form().get("code_verifier"));
            assertNull(r.form().get("client_secret"));
            return new FakePool.Res(200, "{\"access_token\":\"" + at + "\",\"token_type\":\"Bearer\",\"expires_in\":900,"
                    + "\"scope\":\"openid profile email\",\"refresh_token\":\"obur_1\",\"refresh_expires_in\":100,\"id_token\":\"" + idToken + "\"}");
        });
        Map<String, String> params = new HashMap<>();
        params.put("code", "abc");
        params.put("state", tx.getState());
        params.put("iss", pool.issuer);
        OidcWebClient.Result result = oidc.handleCallback(params, restored);
        assertEquals("usr_1", result.getUserId());
        assertEquals("obur_1", result.getTokens().getRefreshToken());
        assertEquals(900, result.getTokens().getExpiresIn());
        assertTrue(!result.getTokens().toString().contains("obur_1"));
        assertEquals(tx.getNonce(), result.getIdTokenClaims().get("nonce"));
    }

    @Test
    void refusesAForgedIdToken() throws Exception {
        AuthorizationRequest tx = oidc.authorizationUrl(null);
        String forged = pool.sign(pool.header("JWT"), pool.accessClaims(CLIENT, System.currentTimeMillis() / 1000 + 60), FakePool.newKeyPair());
        pool.route("POST", "/gateway/shop/auth/main/token", r -> new FakePool.Res(200,
                "{\"access_token\":\"a\",\"expires_in\":900,\"refresh_token\":\"r\",\"id_token\":\"" + forged + "\"}"));
        assertEquals("token_invalid_signature", assertThrows(TokenVerificationException.class,
                () -> oidc.handleCallback("https://app.example.com/callback?code=c&state=" + tx.getState(), tx)).getCode());
        String wrongNonce = pool.idToken(CLIENT, "zzz");
        pool.route("POST", "/gateway/shop/auth/main/token", r -> new FakePool.Res(200,
                "{\"access_token\":\"a\",\"expires_in\":900,\"refresh_token\":\"r\",\"id_token\":\"" + wrongNonce + "\"}"));
        assertEquals("token_invalid_nonce", assertThrows(TokenVerificationException.class,
                () -> oidc.handleCallback("https://app.example.com/callback?code=c&state=" + tx.getState(), tx)).getCode());
        assertEquals("invalid_state", assertThrows(AppAuthException.class,
                () -> oidc.handleCallback("https://app.example.com/callback?code=c&state=x", tx)).getCode());
    }

    @Test
    void clientSecretPostRefreshRevokeUserinfoLogout() throws Exception {
        OidcWebClient post = OidcWebClient.builder(pool.issuer, CLIENT, "s", "https://app/cb")
                .clientAuthMethod(OidcWebClient.ClientAuthMethod.CLIENT_SECRET_POST).build();
        pool.route("POST", "/gateway/shop/auth/main/token", r -> {
            assertNull(r.header("Authorization"));
            assertEquals("s", r.form().get("client_secret"));
            assertEquals(CLIENT, r.form().get("client_id"));
            assertEquals("refresh_token", r.form().get("grant_type"));
            assertEquals("obur_1", r.form().get("refresh_token"));
            assertEquals("org_2", r.form().get("org_id"));
            return new FakePool.Res(200, "{\"access_token\":\"a\",\"expires_in\":900,\"refresh_token\":\"obur_2\",\"org\":{\"id\":\"org_2\",\"name\":\"B\",\"roles\":[],\"choices\":2}}");
        });
        TokenResponse t = post.refresh("obur_1", "org_2");
        assertEquals("obur_2", t.getRefreshToken());
        assertEquals("org_2", t.getOrg().getId());

        pool.route("POST", "/gateway/shop/auth/main/revoke", r -> {
            assertEquals("obur_2", r.form().get("token"));
            assertTrue(r.header("Authorization").startsWith("Basic "));
            return new FakePool.Res(200, "");
        });
        oidc.revoke("obur_2");

        pool.route("GET", "/gateway/shop/auth/main/userinfo", r -> "Bearer tok".equals(r.header("Authorization"))
                ? new FakePool.Res(200, "{\"sub\":\"usr_1\",\"email\":\"a@b\",\"org_id\":null,\"roles\":[]}")
                : new FakePool.Res(401, "{\"error\":\"invalid_token\"}"));
        assertEquals("usr_1", oidc.userinfo("tok").get("sub").asText());
        assertEquals("invalid_token", assertThrows(AppAuthException.class, () -> oidc.userinfo("bad")).getCode());

        pool.route("POST", "/gateway/shop/auth/main/token", r -> new FakePool.Res(400, "{\"error\":\"invalid_grant\",\"error_description\":\"reuse\"}"));
        AppAuthException e = assertThrows(AppAuthException.class, () -> oidc.refresh("old"));
        assertEquals("invalid_grant", e.getCode());

        Map<String, String> q = Util.queryParams(oidc.logoutUrl("idt", "https://app/bye", "s1"));
        assertEquals("idt", q.get("id_token_hint"));
        assertEquals("https://app/bye", q.get("post_logout_redirect_uri"));
        assertEquals(CLIENT, q.get("client_id"));
    }
}
