package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppAuthClientTest {
    private static final String CLIENT = "uapp_desktop";
    private FakePool pool;
    private InMemoryTokenStorage storage;
    private AppAuthClient auth;

    @BeforeEach
    void setUp() throws Exception {
        pool = new FakePool();
        storage = new InMemoryTokenStorage();
        auth = AppAuthClient.builder(pool.issuer + "/", CLIENT).storage(storage).redirectUri("com.example.app:/callback").build();
    }

    @AfterEach
    void tearDown() {
        assertTrue(pool.failures.isEmpty(), () -> "fake pool assertion failed: " + pool.failures);
        pool.close();
    }

    private String okOutcome(String rt, long expiresIn) throws Exception {
        return "{\"status\":\"ok\",\"access_token\":\"" + pool.accessToken(CLIENT) + "\",\"token_type\":\"Bearer\",\"refresh_token\":\""
                + rt + "\",\"expires_in\":" + expiresIn + ",\"user\":" + FakePool.userJson("usr_1") + ",\"org\":null}";
    }

    private String tokens(String rt, long expiresIn) throws Exception {
        return "{\"access_token\":\"" + pool.accessToken(CLIENT) + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn
                + ",\"scope\":\"openid\",\"refresh_token\":\"" + rt + "\",\"refresh_expires_in\":1000}";
    }

    private void signIn(String rt, long expiresIn) throws Exception {
        String body = okOutcome(rt, expiresIn);
        pool.api("POST", "/api/v1/signin/password", r -> new FakePool.Res(200, body));
        assertTrue(auth.signInWithPassword("ada@example.com", "pw").isOk());
    }

    @Test
    void passwordSignInKeepsTheSessionAndTellsListeners() throws Exception {
        List<String> seen = new ArrayList<>();
        Subscription sub = auth.onAuthStateChanged((u, o) -> seen.add(u == null ? "out" : u.getId()));
        assertEquals(List.of("out"), seen);                                     // called immediately

        signIn("obur_1", 900);
        assertEquals(List.of("out", "usr_1"), seen);
        assertTrue(auth.isSignedIn());
        assertEquals("Ada", auth.getCurrentUser().getDisplayName());
        assertEquals("pro", auth.getCurrentUser().getAttributes().get("plan"));
        assertEquals("usr_1", auth.getAccessTokenClaims().get("sub"));

        FakePool.Req req = pool.requests.get(pool.requests.size() - 1);
        assertEquals(CLIENT, req.header("X-Client-Id"));
        assertEquals("application/json", req.header("Accept"));
        assertTrue(req.header("Content-Type").startsWith("application/json"));
        assertNull(req.header("Origin"));
        assertEquals("ada@example.com", req.json().get("email").asText());
        assertFalse(req.json().has("org_id"));                                 // nulls are not sent

        JsonNode stored = Json.parse(storage.get("openback.auth." + CLIENT));
        assertEquals("obur_1", stored.get("refreshToken").asText());
        assertTrue(stored.get("expiresAt").asLong() > System.currentTimeMillis());
        assertEquals("usr_1", stored.get("user").get("id").asText());
        assertTrue(stored.has("accessToken"));

        // a new client on the same storage restores the session
        AppAuthClient again = AppAuthClient.builder(pool.issuer, CLIENT).storage(storage).build();
        assertEquals("usr_1", again.getCurrentUser().getId());

        sub.close();
        auth.signOut();
        assertEquals(2, seen.size());                                          // unsubscribed
    }

    @Test
    void otherOutcomesDoNotSignIn() throws Exception {
        pool.api("POST", "/api/v1/signin/password", r -> new FakePool.Res(200, "{\"status\":\"mfa_required\",\"mfa_token\":\"mfa_1\"}"));
        AuthOutcome res = auth.signInWithPassword("ada@example.com", "pw");
        assertEquals(AuthOutcome.Status.MFA_REQUIRED, res.getStatus());
        assertEquals("mfa_1", res.getMfaToken());
        assertFalse(auth.isSignedIn());

        String ok = okOutcome("obur_9", 900);
        pool.api("POST", "/api/v1/signin/mfa", r -> new FakePool.Res(200, ok));
        AuthOutcome done = auth.verifyMfa("mfa_1", "123456");
        assertTrue(done.isOk());
        assertEquals("usr_1", done.getUser().getId());
        assertFalse(done.getDetails().has("access_token"));                    // tokens never exposed
        assertTrue(auth.isSignedIn());
        FakePool.Req req = pool.requests.get(pool.requests.size() - 1);
        assertEquals("mfa_1", req.json().get("mfa_token").asText());

        pool.api("POST", "/api/v1/signup", r -> new FakePool.Res(200, "{\"status\":\"password_change_required\",\"change_token\":\"chg\"}"));
        assertEquals("chg", auth.signUp("b@example.com", "pw").getChangeToken());
        pool.api("POST", "/api/v1/signin/email-code/verify", r -> new FakePool.Res(200, "{\"status\":\"verification_required\"}"));
        assertEquals(AuthOutcome.Status.VERIFICATION_REQUIRED, auth.signInWithEmailCode("a@b.c", "1").getStatus());
        pool.api("POST", "/api/v1/signin/anonymous", r -> new FakePool.Res(200, "{\"status\":\"something_new\"}"));
        AuthOutcome unknown = auth.signInAnonymously();
        assertEquals(AuthOutcome.Status.UNKNOWN, unknown.getStatus());
        assertEquals("something_new", unknown.getRawStatus());
    }

    @Test
    void mapsErrors() {
        pool.api("POST", "/api/v1/signin/password", r -> new FakePool.Res(401,
                "{\"detail\":{\"code\":\"invalid_credentials\",\"message\":\"Wrong email or password\"}}"));
        AppAuthException e = assertThrows(AppAuthException.class, () -> auth.signInWithPassword("a@b.c", "x"));
        assertEquals(401, e.getStatus());
        assertEquals("invalid_credentials", e.getCode());
        assertEquals("Wrong email or password", e.getMessage());

        pool.api("POST", "/api/v1/signup", r -> new FakePool.Res(422,
                "{\"detail\":{\"code\":\"weak_password\",\"message\":\"Weak\",\"problems\":[\"min_length\"]}}"));
        AppAuthException weak = assertThrows(AppAuthException.class, () -> auth.signUp("a@b.c", "x"));
        assertEquals("weak_password", weak.getCode());
        assertEquals("min_length", weak.getDetail().get("problems").get(0).asText());

        pool.api("POST", "/api/v1/password/forgot", r -> new FakePool.Res(422, "{\"detail\":[{\"loc\":[\"body\",\"email\"]}]}"));
        assertEquals("http_422", assertThrows(AppAuthException.class, () -> auth.sendPasswordReset("x")).getCode());

        pool.api("POST", "/api/v1/signin/email-code", r -> new FakePool.Res(429, "{\"detail\":\"Too many\"}"));
        AppAuthException tooMany = assertThrows(AppAuthException.class, () -> auth.sendEmailCode("x"));
        assertEquals("http_429", tooMany.getCode());
        assertEquals("Too many", tooMany.getMessage());

        assertEquals("not_signed_in", assertThrows(AppAuthException.class, () -> auth.getAccessToken()).getCode());
    }

    @Test
    void freshTokenIsReusedAndAnExpiringOneIsRefreshed() throws Exception {
        signIn("obur_1", 900);
        String first = auth.getAccessToken();
        assertEquals(first, auth.getAccessToken());
        assertEquals(0, pool.hits("POST", "/api/v1/token/refresh"));

        signIn("obur_2", 30);                                                  // expires in < 60 s
        String body = tokens("obur_3", 900);
        pool.api("POST", "/api/v1/token/refresh", r -> {
            assertEquals("obur_2", r.json().get("refresh_token").asText());
            return new FakePool.Res(200, body);
        });
        auth.getAccessToken();
        assertEquals(1, pool.hits("POST", "/api/v1/token/refresh"));
        assertEquals("obur_3", Json.parse(storage.get("openback.auth." + CLIENT)).get("refreshToken").asText());
        assertEquals("usr_1", auth.getCurrentUser().getId());                  // user kept across refreshes
    }

    @Test
    void refreshIsSingleFlight() throws Exception {
        signIn("obur_1", 10);
        AtomicInteger calls = new AtomicInteger();
        String body = tokens("obur_2", 900);
        pool.api("POST", "/api/v1/token/refresh", r -> {
            calls.incrementAndGet();
            if (!"obur_1".equals(r.json().get("refresh_token").asText())) {
                return new FakePool.Res(401, "{\"detail\":{\"code\":\"invalid_refresh_token\",\"message\":\"reuse\"}}");
            }
            Thread.sleep(300);
            return new FakePool.Res(200, body);
        });
        int n = 12;
        ExecutorService ex = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> results = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            results.add(ex.submit((Callable<String>) () -> {
                start.await();
                return auth.getAccessToken();
            }));
        }
        start.countDown();
        String token = results.get(0).get();
        for (Future<String> f : results) {
            assertEquals(token, f.get());
        }
        ex.shutdown();
        assertEquals(1, calls.get());
        assertTrue(auth.isSignedIn());
    }

    @Test
    void invalidRefreshTokenEndsTheSession() throws Exception {
        signIn("obur_1", 10);
        List<String> seen = new ArrayList<>();
        auth.onAuthStateChanged((u, o) -> seen.add(u == null ? "out" : u.getId()));
        pool.api("POST", "/api/v1/token/refresh", r -> new FakePool.Res(401,
                "{\"detail\":{\"code\":\"invalid_refresh_token\",\"message\":\"Session expired\"}}"));
        AppAuthException e = assertThrows(AppAuthException.class, () -> auth.getAccessToken());
        assertEquals("invalid_refresh_token", e.getCode());
        assertTrue(e.isSessionEnded());
        assertFalse(auth.isSignedIn());
        assertNull(storage.get("openback.auth." + CLIENT));
        assertEquals(List.of("usr_1", "out"), seen);
    }

    @Test
    void networkErrorDuringRefreshIsNotRetriedAndKeepsTheSession() throws Exception {
        signIn("obur_1", 10);
        pool.api("POST", "/api/v1/token/refresh", r -> null);                  // connection dropped
        AppAuthException e = assertThrows(AppAuthException.class, () -> auth.getAccessToken());
        assertEquals("network_error", e.getCode());
        assertEquals(1, pool.hits("POST", "/api/v1/token/refresh"));
        assertTrue(auth.isSignedIn());
        assertEquals("obur_1", Json.parse(storage.get("openback.auth." + CLIENT)).get("refreshToken").asText());
    }

    @Test
    void tokenErrorOnASignedInCallClearsTheSession() throws Exception {
        signIn("obur_1", 900);
        pool.api("GET", "/api/v1/me", r -> new FakePool.Res(401, "{\"detail\":{\"code\":\"token_revoked\",\"message\":\"x\"}}"));
        assertEquals("token_revoked", assertThrows(AppAuthException.class, () -> auth.me()).getCode());
        assertFalse(auth.isSignedIn());
    }

    @Test
    void signedInCallsSendTheBearerToken() throws Exception {
        signIn("obur_1", 900);
        String token = auth.getAccessToken();
        pool.api("GET", "/api/v1/me", r -> new FakePool.Res(200, FakePool.userJson("usr_1").replace("\"Ada\"", "\"Ada L.\"")));
        assertEquals("Ada L.", auth.me().getDisplayName());
        assertEquals("Bearer " + token, pool.requests.get(pool.requests.size() - 1).header("Authorization"));
        assertEquals("Ada L.", auth.getCurrentUser().getDisplayName());

        pool.api("PATCH", "/api/v1/me", r -> new FakePool.Res(200, FakePool.userJson("usr_1").replace("\"en\"", "\"it\"")));
        assertEquals("it", auth.updateProfile(new ProfileUpdate().locale("it")).getLocale());
        assertEquals("it", pool.requests.get(pool.requests.size() - 1).json().get("locale").asText());

        pool.api("GET", "/api/v1/orgs", r -> new FakePool.Res(200, "{\"orgs\":[{\"id\":\"org_1\",\"name\":\"Acme\",\"roles\":[\"owner\"],\"disabled\":false}],\"active\":\"org_1\"}"));
        OrganizationList orgs = auth.organizations();
        assertEquals("Acme", orgs.getOrgs().get(0).getName());
        assertEquals("org_1", orgs.getActive());

        pool.api("GET", "/api/v1/orgs/org%201/members", r -> {
            assertEquals("q=ada&skip=10&limit=5", r.query);
            return new FakePool.Res(200, "{\"items\":[{\"user_id\":\"usr_2\",\"email\":\"b@x\",\"display_name\":\"B\",\"disabled\":false,\"roles\":[\"member\"],\"created_at\":\"t\"}],\"total\":1,\"roles\":[{\"key\":\"member\",\"label\":\"Member\"}]}");
        });
        MemberPage page = auth.members("org 1", "ada", 10, 5);
        assertEquals("usr_2", page.getItems().get(0).getUserId());
        assertEquals("Member", page.getRoles().get(0).getLabel());

        pool.api("POST", "/api/v1/mfa/enroll", r -> new FakePool.Res(200, "{\"secret\":\"ABC\",\"otpauth_uri\":\"otpauth://totp/x\"}"));
        MfaEnrollment en = auth.enrollMfa();
        assertEquals("otpauth://totp/x", en.getOtpauthUri());
        assertFalse(en.toString().contains("ABC"));
        pool.api("POST", "/api/v1/mfa/enroll/confirm", r -> new FakePool.Res(200, "{\"status\":\"enabled\",\"recovery_codes\":[\"r1\",\"r2\"]}"));
        assertEquals(List.of("r1", "r2"), auth.confirmMfa("123456").getRecoveryCodes());
    }

    @Test
    void switchOrganizationRotatesUnderTheLock() throws Exception {
        signIn("obur_1", 900);
        String body = tokens("obur_2", 900).replace("}", ",\"org\":{\"id\":\"org_2\",\"name\":\"Beta\",\"roles\":[\"admin\"],\"choices\":2}}");
        pool.api("POST", "/api/v1/orgs/switch", r -> {
            assertEquals("obur_1", r.json().get("refresh_token").asText());
            assertEquals("org_2", r.json().get("org_id").asText());
            assertNotNull(r.header("Authorization"));
            return new FakePool.Res(200, body);
        });
        ActiveOrg org = auth.switchOrganization("org_2");
        assertEquals("Beta", org.getName());
        assertEquals(2, org.getChoices());
        assertEquals("org_2", auth.getCurrentOrg().getId());
        assertEquals("obur_2", Json.parse(storage.get("openback.auth." + CLIENT)).get("refreshToken").asText());
    }

    @Test
    void changePasswordAndDeleteAccountClearTheSession() throws Exception {
        signIn("obur_1", 900);
        pool.api("POST", "/api/v1/me/password", r -> new FakePool.Res(200, "{\"status\":\"password_changed\"}"));
        auth.changePassword("old", "new-password-123");
        assertFalse(auth.isSignedIn());

        signIn("obur_2", 900);
        pool.api("DELETE", "/api/v1/me", r -> {
            assertEquals("pw", r.json().get("password").asText());
            return new FakePool.Res(200, "{\"status\":\"deleted\"}");
        });
        auth.deleteAccount("pw");
        assertFalse(auth.isSignedIn());
    }

    @Test
    void signOutIsBestEffortAndAlwaysClears() throws Exception {
        signIn("obur_1", 900);
        pool.api("POST", "/api/v1/signout", r -> new FakePool.Res(500, "{}"));
        auth.signOut(true);
        assertFalse(auth.isSignedIn());
        FakePool.Req req = pool.requests.get(pool.requests.size() - 1);
        assertEquals("obur_1", req.json().get("refresh_token").asText());
        assertTrue(req.json().get("everywhere").asBoolean());
        assertNull(storage.get("openback.auth." + CLIENT));
    }

    @Test
    void upgradeAndVerifyUpdateTheStoredUser() throws Exception {
        signIn("obur_1", 900);
        pool.api("POST", "/api/v1/me/upgrade", r -> new FakePool.Res(200,
                "{\"status\":\"upgraded\",\"user\":" + FakePool.userJson("usr_1").replace("ada@", "new@") + "}"));
        assertEquals("new@example.com", auth.upgradeAnonymous("new@example.com", "pw").getEmail());
        assertEquals("new@example.com", auth.getCurrentUser().getEmail());
    }

    // --- hosted sign-in ----------------------------------------------------------------------------------------------

    @Test
    void buildsTheAuthorizationRequestWithPkce() {
        AuthorizationRequest req = auth.buildAuthorizationRequest(new AuthorizationOptions().provider("uprov_g").orgId("org_1")
                .prompt("login").screenHint("signup").loginHint("a@b.c").maxAge(300).uiLocales("it"));
        Map<String, String> q = Util.queryParams(req.getUrl());
        assertTrue(req.getUrl().startsWith(pool.issuer + "/authorize?"));
        assertEquals("code", q.get("response_type"));
        assertEquals(CLIENT, q.get("client_id"));
        assertEquals("com.example.app:/callback", q.get("redirect_uri"));
        assertEquals("openid profile email", q.get("scope"));
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals(Util.codeChallenge(req.getCodeVerifier()), q.get("code_challenge"));
        assertEquals(req.getState(), q.get("state"));
        assertEquals(req.getNonce(), q.get("nonce"));
        assertEquals("uprov_g", q.get("provider"));
        assertEquals("org_1", q.get("org_id"));
        assertEquals("login", q.get("prompt"));
        assertEquals("signup", q.get("screen_hint"));
        assertEquals("a@b.c", q.get("login_hint"));
        assertEquals("300", q.get("max_age"));
        assertEquals("it", q.get("ui_locales"));
        assertTrue(req.getCodeVerifier().length() >= 43 && req.getCodeVerifier().length() <= 128);
        assertNotNull(storage.get("openback.auth." + CLIENT + ".pkce"));
        assertFalse(req.toString().contains(req.getCodeVerifier()));
        // two requests never share secrets
        AuthorizationRequest other = auth.buildAuthorizationRequest(null);
        assertFalse(other.getState().equals(req.getState()) || other.getCodeVerifier().equals(req.getCodeVerifier()));
    }

    @Test
    void handlesTheRedirectCallback() throws Exception {
        AuthorizationRequest req = auth.buildAuthorizationRequest(null);
        String idToken = pool.idToken(CLIENT, req.getNonce());
        String at = pool.accessToken(CLIENT);
        pool.route("POST", "/gateway/shop/auth/main/token", r -> {
            Map<String, String> f = r.form();
            assertEquals("authorization_code", f.get("grant_type"));
            assertEquals("the-code", f.get("code"));
            assertEquals(req.getCodeVerifier(), f.get("code_verifier"));
            assertEquals("com.example.app:/callback", f.get("redirect_uri"));
            assertEquals(CLIENT, f.get("client_id"));
            assertNull(r.header("Authorization"));                             // public client
            return new FakePool.Res(200, "{\"access_token\":\"" + at + "\",\"token_type\":\"Bearer\",\"expires_in\":900,"
                    + "\"refresh_token\":\"obur_x\",\"refresh_expires_in\":100,\"id_token\":\"" + idToken + "\"}");
        });
        pool.api("GET", "/api/v1/me", r -> new FakePool.Res(200, FakePool.userJson("usr_1")));
        // a new client instance (the app restarted while the browser was open) completes it from the storage
        AppAuthClient restarted = AppAuthClient.builder(pool.issuer, CLIENT).storage(storage).build();
        PoolUser user = restarted.handleRedirectCallback("com.example.app:/callback?code=the-code&state=" + req.getState()
                + "&iss=" + Util.encode(pool.issuer));
        assertEquals("usr_1", user.getId());
        assertTrue(restarted.isSignedIn());
        assertNull(storage.get("openback.auth." + CLIENT + ".pkce"));          // one use
        assertTrue(restarted.buildLogoutUrl("com.example.app:/bye", "s1").contains("id_token_hint=" + idToken));
    }

    @Test
    void callbackChecks() throws Exception {
        AuthorizationRequest req = auth.buildAuthorizationRequest(null);
        assertEquals("invalid_state", assertThrows(AppAuthException.class,
                () -> auth.handleRedirectCallback("com.example.app:/callback?code=c&state=wrong")).getCode());
        assertEquals("invalid_issuer", assertThrows(AppAuthException.class,
                () -> auth.handleRedirectCallback("com.example.app:/callback?code=c&state=" + req.getState() + "&iss=https://evil")).getCode());
        AppAuthException denied = assertThrows(AppAuthException.class,
                () -> auth.handleRedirectCallback("com.example.app:/callback?error=login_required&error_description=No+session&state=" + req.getState()));
        assertEquals("login_required", denied.getCode());
        assertEquals("No session", denied.getMessage());
        assertEquals("no_pending_request", assertThrows(AppAuthException.class,
                () -> auth.handleRedirectCallback("com.example.app:/callback?code=c&state=" + req.getState())).getCode());
        assertEquals(0, pool.rawHits("POST", "/gateway/shop/auth/main/token"));

        AuthorizationRequest again = auth.buildAuthorizationRequest(null);
        String badNonce = pool.idToken(CLIENT, "not-the-nonce");
        pool.route("POST", "/gateway/shop/auth/main/token", r -> new FakePool.Res(200,
                "{\"access_token\":\"a\",\"expires_in\":900,\"refresh_token\":\"r\",\"id_token\":\"" + badNonce + "\"}"));
        assertEquals("invalid_nonce", assertThrows(AppAuthException.class,
                () -> auth.handleRedirectCallback("com.example.app:/callback?code=c&state=" + again.getState())).getCode());
        assertFalse(auth.isSignedIn());

        auth.buildAuthorizationRequest(null);
        AuthorizationRequest third = AuthorizationRequest.fromJson(storage.get("openback.auth." + CLIENT + ".pkce"));
        pool.route("POST", "/gateway/shop/auth/main/token", r -> new FakePool.Res(400,
                "{\"error\":\"invalid_grant\",\"error_description\":\"invalid or expired code\"}"));
        AppAuthException grant = assertThrows(AppAuthException.class,
                () -> auth.handleRedirectCallback("com.example.app:/callback?code=c&state=" + third.getState()));
        assertEquals("invalid_grant", grant.getCode());
        assertEquals(400, grant.getStatus());
    }

    @Test
    void confidentialClientSendsBasicAuthOnTheExchange() throws Exception {
        AppAuthClient web = AppAuthClient.builder(pool.issuer, "uapp_web").clientSecret("s3cr:et").redirectUri("https://app/cb")
                .storage(new InMemoryTokenStorage()).build();
        AuthorizationRequest req = web.buildAuthorizationRequest(null);
        pool.route("POST", "/gateway/shop/auth/main/token", r -> {
            assertEquals(Util.basicAuth("uapp_web", "s3cr:et"), r.header("Authorization"));
            return new FakePool.Res(200, "{\"access_token\":\"a\",\"expires_in\":900,\"refresh_token\":\"r\"}");
        });
        pool.api("GET", "/api/v1/me", r -> new FakePool.Res(200, FakePool.userJson("usr_1")));
        assertEquals("usr_1", web.handleRedirectCallback("https://app/cb?code=c&state=" + req.getState()).getId());
    }

    @Test
    void logoutUrlAndAsync() throws Exception {
        String url = auth.buildLogoutUrl("com.example.app:/bye", "st");
        Map<String, String> q = Util.queryParams(url);
        assertTrue(url.startsWith(pool.issuer + "/logout?"));
        assertEquals(CLIENT, q.get("client_id"));
        assertEquals("com.example.app:/bye", q.get("post_logout_redirect_uri"));
        assertEquals("st", q.get("state"));
        assertFalse(q.containsKey("id_token_hint"));

        signIn("obur_1", 900);
        assertEquals(auth.getAccessToken(), auth.getAccessTokenAsync().get());
        pool.api("GET", "/api/v1/config", r -> new FakePool.Res(200, "{\"mode\":\"b2c\"}"));
        assertEquals("b2c", auth.async(auth::config).get().get("mode").asText());
    }
}
