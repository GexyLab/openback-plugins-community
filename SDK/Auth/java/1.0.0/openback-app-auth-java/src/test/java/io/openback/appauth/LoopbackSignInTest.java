package io.openback.appauth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoopbackSignInTest {
    @Test
    void completesTheFlowThroughTheLoopbackListener() throws Exception {
        try (FakePool pool = new FakePool(); LoopbackSignIn loopback = LoopbackSignIn.start(0, "/callback")) {
            assertTrue(loopback.getRedirectUri().matches("http://127\\.0\\.0\\.1:\\d+/callback"));
            AppAuthClient auth = AppAuthClient.create(pool.issuer, "uapp_cli");
            String[] nonce = new String[1];
            pool.route("POST", "/gateway/shop/auth/main/token", r -> {
                assertEquals(loopback.getRedirectUri(), r.form().get("redirect_uri"));
                return new FakePool.Res(200, "{\"access_token\":\"" + pool.accessToken("uapp_cli") + "\",\"expires_in\":900,"
                        + "\"refresh_token\":\"obur_1\",\"id_token\":\"" + pool.idToken("uapp_cli", nonce[0]) + "\"}");
            });
            pool.api("GET", "/api/v1/me", r -> new FakePool.Res(200, FakePool.userJson("usr_1")));

            HttpClient browser = HttpClient.newHttpClient();
            PoolUser user = loopback.signIn(auth, new AuthorizationOptions(), Duration.ofSeconds(10), url -> {
                // the "browser": the hosted page redirects back to the loopback address
                Map<String, String> q = Util.queryParams(url);
                nonce[0] = q.get("nonce");
                String back = q.get("redirect_uri") + "?code=abc&state=" + q.get("state") + "&iss=" + Util.encode(pool.issuer);
                CompletableFuture.runAsync(() -> {
                    try {
                        HttpResponse<String> res = browser.send(HttpRequest.newBuilder(URI.create(back)).build(), HttpResponse.BodyHandlers.ofString());
                        assertEquals(200, res.statusCode());
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
            });
            assertEquals("usr_1", user.getId());
            assertTrue(auth.isSignedIn());
            assertTrue(pool.failures.isEmpty(), () -> pool.failures.toString());
        }
    }

    @Test
    void timesOut() throws Exception {
        try (LoopbackSignIn loopback = LoopbackSignIn.start(0, "cb")) {
            assertEquals("timeout", assertThrows(AppAuthException.class, () -> loopback.awaitCallback(Duration.ofMillis(100))).getCode());
        }
    }
}
