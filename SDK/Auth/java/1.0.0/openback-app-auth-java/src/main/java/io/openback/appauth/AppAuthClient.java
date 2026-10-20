package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * The client of an OpenBack user pool ("App authenticator") for Java apps: desktop, CLI, and server-side calls.
 *
 * <p>Two ways to sign users in, freely mixed: your own forms through the pool's JSON API ({@link #signInWithPassword},
 * {@link #signUp}, {@link #signInWithEmailCode}, {@link #signInAnonymously}, {@link #verifyMfa}...), or the pool's hosted
 * sign-in page (OpenID Connect, code + PKCE: {@link #buildAuthorizationRequest} + {@link #handleRedirectCallback}, or
 * {@link LoopbackSignIn} for desktop apps).
 *
 * <p>The session lives in a {@link TokenStorage} (in memory by default). {@link #getAccessToken()} renews the access token
 * when it expires in less than 60 seconds, ONE refresh at a time (refresh tokens rotate at every use: a second concurrent
 * refresh with the same token would revoke the session). Methods are blocking and thread-safe; {@link #async(Supplier)}
 * runs any of them on the client's executor.
 *
 * <pre>{@code
 * AppAuthClient auth = AppAuthClient.builder("https://api.example.com/gateway/shop/auth/main", "uapp_...").build();
 * AuthOutcome res = auth.signInWithPassword("ada@example.com", password);
 * if (res.getStatus() == AuthOutcome.Status.MFA_REQUIRED) res = auth.verifyMfa(res.getMfaToken(), code);
 * String token = auth.getAccessToken();
 * }</pre>
 */
public final class AppAuthClient {
    static final String API = "/api/v1";
    static final long SKEW_MS = 60_000L;

    private final String issuer;
    private final String clientId;
    private final String redirectUri;
    private final String clientSecret;
    private final String storageKey;
    private final TokenStorage storage;
    private final HttpClient http;
    private final Duration timeout;
    private final Clock clock;
    private final Executor executor;
    private final ReentrantLock refreshLock = new ReentrantLock();
    private final List<AuthStateListener> listeners = new CopyOnWriteArrayList<>();
    private volatile Session state;

    private AppAuthClient(Builder b) {
        this.issuer = Util.normalizeIssuer(b.issuer);
        if (b.clientId == null || b.clientId.isBlank()) {
            throw new IllegalArgumentException("clientId is required");
        }
        this.clientId = b.clientId;
        this.redirectUri = b.redirectUri;
        this.clientSecret = b.clientSecret;
        this.storageKey = b.storageKey != null ? b.storageKey : "openback.auth." + b.clientId;
        this.storage = b.storage != null ? b.storage : new InMemoryTokenStorage();
        this.http = b.httpClient != null ? b.httpClient : Http.defaultClient();
        this.timeout = b.timeout != null ? b.timeout : Http.DEFAULT_TIMEOUT;
        this.clock = b.clock != null ? b.clock : Clock.systemUTC();
        this.executor = b.executor != null ? b.executor : DefaultExecutor.INSTANCE;
        this.state = load();
    }

    /** A builder: {@code issuer} is the pool's address (a trailing slash is removed), {@code clientId} the app's {@code uapp_...}. */
    public static Builder builder(String issuer, String clientId) {
        return new Builder(issuer, clientId);
    }

    /** {@code builder(issuer, clientId).build()}. */
    public static AppAuthClient create(String issuer, String clientId) {
        return builder(issuer, clientId).build();
    }

    // --- state -------------------------------------------------------------------------------------------------------

    public String getIssuer() {
        return issuer;
    }

    public String getClientId() {
        return clientId;
    }

    /** The signed-in user (as last read), or null. */
    public PoolUser getCurrentUser() {
        Session s = state;
        return s == null ? null : s.typedUser();
    }

    /** The active organization (B2B pools), or null. */
    public ActiveOrg getCurrentOrg() {
        Session s = state;
        return s == null ? null : s.typedOrg();
    }

    /** The access token's claims, decoded but NOT verified (for display); empty when signed out. */
    public Map<String, Object> getAccessTokenClaims() {
        Session s = state;
        JsonNode claims = s == null ? null : Util.decodeJwtPayload(s.accessToken);
        return claims == null ? Collections.emptyMap() : Json.toMap(claims);
    }

    /** True when a session is kept (a refresh token, or an access token still valid). */
    public boolean isSignedIn() {
        Session s = state;
        return s != null && (s.refreshToken != null || fresh(s));
    }

    /**
     * Registers a listener of sign-ins, sign-outs and user/organization changes. It is called immediately with the
     * current state, then at every change (on the thread that made it). Returns the subscription: close it to stop.
     */
    public Subscription onAuthStateChanged(AuthStateListener listener) {
        Objects.requireNonNull(listener, "listener");
        listeners.add(listener);
        safeNotify(listener, getCurrentUser(), getCurrentOrg());
        return () -> listeners.remove(listener);
    }

    // --- tokens ------------------------------------------------------------------------------------------------------

    /**
     * A valid access token: the stored one if it expires in more than 60 seconds, else a refreshed one (single-flight).
     *
     * @throws AppAuthException {@code not_signed_in}; {@code invalid_refresh_token} (the session ended: cleared and
     *                          listeners notified); {@code network_error} (not retried: the next call tries again)
     */
    public String getAccessToken() {
        Session s = state;
        if (s != null && fresh(s)) {
            return s.accessToken;
        }
        return refresh(null);
    }

    /** {@link #getAccessToken()} on the client's executor. */
    public CompletableFuture<String> getAccessTokenAsync() {
        return async(this::getAccessToken);
    }

    /** Renews the tokens now. */
    public String refresh() {
        return refresh(null);
    }

    /**
     * Renews the tokens now, optionally for another organization ({@code orgId}, B2B). One refresh at a time: callers that
     * waited for a refresh in progress get its result instead of starting another one.
     */
    public String refresh(String orgId) {
        Session before = state;
        if (before == null || before.refreshToken == null) {
            throw notSignedIn();
        }
        refreshLock.lock();
        try {
            Session cur = state;
            if (cur == null || cur.refreshToken == null) {
                throw notSignedIn();
            }
            if (orgId == null && !Objects.equals(cur.refreshToken, before.refreshToken) && fresh(cur)) {
                return cur.accessToken;            // renewed by the refresh we waited for
            }
            Session stored = load();               // another client sharing the storage may have rotated it
            if (stored != null && !Objects.equals(stored.refreshToken, cur.refreshToken)) {
                state = stored;
                cur = stored;
                if (orgId == null && fresh(cur)) {
                    return cur.accessToken;
                }
            }
            JsonNode data;
            try {
                data = call("POST", "/token/refresh", Json.object("refresh_token", cur.refreshToken, "org_id", orgId), false, null);
            } catch (AppAuthException e) {
                if (e.getStatus() == 401) {
                    clearSession();
                }
                throw e;
            }
            saveTokens(data, cur.user);
            return state.accessToken;
        } finally {
            refreshLock.unlock();
        }
    }

    /** {@link #refresh(String)} on the client's executor. */
    public CompletableFuture<String> refreshAsync(String orgId) {
        return async(() -> refresh(orgId));
    }

    /** Runs any call of this client on its executor: {@code auth.async(() -> auth.me())}. */
    public <T> CompletableFuture<T> async(Supplier<T> call) {
        return CompletableFuture.supplyAsync(call, executor);
    }

    // --- your API ----------------------------------------------------------------------------------------------------

    /** Sets {@code Authorization: Bearer <access token>} on a request of yours (renewing the token if needed). */
    public HttpRequest.Builder authorize(HttpRequest.Builder request) {
        return request.setHeader("Authorization", "Bearer " + getAccessToken());
    }

    /** Sends a request of yours with the user's access token. */
    public <T> HttpResponse<T> send(HttpRequest.Builder request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        return http.send(authorize(request).build(), handler);
    }

    /** Sends a request of yours with the user's access token, asynchronously. */
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest.Builder request, HttpResponse.BodyHandler<T> handler) {
        return getAccessTokenAsync().thenCompose(token ->
                http.sendAsync(request.setHeader("Authorization", "Bearer " + token).build(), handler));
    }

    // --- pool --------------------------------------------------------------------------------------------------------

    /** {@code GET /config}: methods, providers ({@code start_url}), password policy, mode, branding. */
    public JsonNode config() {
        return call("GET", "/config", null, false, null);
    }

    // --- sign-up and sign-in -----------------------------------------------------------------------------------------

    public AuthOutcome signUp(String email, String password) {
        return signUp(email, password, null, null, null);
    }

    /** Creates an account. {@code displayName}, {@code locale} ("it"/"en"), {@code orgId} (B2B) may be null. */
    public AuthOutcome signUp(String email, String password, String displayName, String locale, String orgId) {
        return outcome(call("POST", "/signup", Json.object("email", email, "password", password,
                "display_name", displayName != null ? displayName : "", "locale", locale, "org_id", orgId), false, null));
    }

    public AuthOutcome signInWithPassword(String email, String password) {
        return signInWithPassword(email, password, null);
    }

    public AuthOutcome signInWithPassword(String email, String password, String orgId) {
        return outcome(call("POST", "/signin/password", Json.object("email", email, "password", password, "org_id", orgId), false, null));
    }

    /** Sends a one-time sign-in code by email. Always answers {@code {status: "sent"}}. */
    public JsonNode sendEmailCode(String email) {
        return call("POST", "/signin/email-code", Json.object("email", email), false, null);
    }

    public AuthOutcome signInWithEmailCode(String email, String code) {
        return signInWithEmailCode(email, code, null);
    }

    public AuthOutcome signInWithEmailCode(String email, String code, String orgId) {
        return outcome(call("POST", "/signin/email-code/verify", Json.object("email", email, "code", code, "org_id", orgId), false, null));
    }

    /** Signs in with the token of an emailed sign-in link. */
    public AuthOutcome signInWithEmailLinkToken(String token, String orgId) {
        return outcome(call("POST", "/signin/email-code/verify", Json.object("token", token, "org_id", orgId), false, null));
    }

    /** A guest account (if the pool allows it); {@link #upgradeAnonymous} turns it into a real one. */
    public AuthOutcome signInAnonymously() {
        return outcome(call("POST", "/signin/anonymous", null, false, null));
    }

    /** Second step of a sign-in: the authenticator (TOTP) code or a recovery code. */
    public AuthOutcome verifyMfa(String mfaToken, String code) {
        return outcome(call("POST", "/signin/mfa", Json.object("mfa_token", mfaToken, "code", code), false, null));
    }

    /** Starts two-step verification for the signed-in user. */
    public MfaEnrollment enrollMfa() {
        return Json.convert(call("POST", "/mfa/enroll", Collections.emptyMap(), true, null), MfaEnrollment.class);
    }

    /** Starts two-step verification during a sign-in ({@link AuthOutcome.Status#MFA_ENROLL_REQUIRED}). */
    public MfaEnrollment enrollMfa(String mfaToken) {
        if (mfaToken == null) {
            return enrollMfa();
        }
        return Json.convert(call("POST", "/mfa/enroll", Json.object("mfa_token", mfaToken), false, null), MfaEnrollment.class);
    }

    /** Confirms the enrollment of the signed-in user with a first code. */
    public MfaConfirmation confirmMfa(String code) {
        JsonNode data = call("POST", "/mfa/enroll/confirm", Json.object("code", code), true, null);
        return new MfaConfirmation(AuthOutcome.of(data).getRecoveryCodes(), null);
    }

    /** Confirms an enrollment made during a sign-in: also completes the sign-in. */
    public MfaConfirmation confirmMfa(String code, String mfaToken) {
        if (mfaToken == null) {
            return confirmMfa(code);
        }
        AuthOutcome out = outcome(call("POST", "/mfa/enroll/confirm", Json.object("mfa_token", mfaToken, "code", code), false, null));
        return new MfaConfirmation(out.getRecoveryCodes(), out);
    }

    /** Turns two-step verification off (a current code is required). */
    public JsonNode disableMfa(String code) {
        return call("POST", "/mfa/disable", Json.object("code", code), true, null);
    }

    // --- passwords and emails ----------------------------------------------------------------------------------------

    /** Sends a password reset email. Always answers {@code {status: "sent"}}. */
    public JsonNode sendPasswordReset(String email) {
        return call("POST", "/password/forgot", Json.object("email", email), false, null);
    }

    /** Resets the password with the token of the reset link. */
    public JsonNode resetPasswordWithToken(String token, String newPassword) {
        return call("POST", "/password/reset", Json.object("token", token, "new_password", newPassword), false, null);
    }

    /** Resets the password with the emailed code. */
    public JsonNode resetPasswordWithCode(String email, String code, String newPassword) {
        return call("POST", "/password/reset", Json.object("email", email, "code", code, "new_password", newPassword), false, null);
    }

    /** Continues {@link AuthOutcome.Status#PASSWORD_CHANGE_REQUIRED}; then sign in again with the new password. */
    public JsonNode changeForcedPassword(String changeToken, String newPassword) {
        return call("POST", "/password/reset", Json.object("change_token", changeToken, "new_password", newPassword), false, null);
    }

    /** Verifies the email with the token of the verification link; returns the user. */
    public PoolUser verifyEmailWithToken(String token) {
        return userAnswer(call("POST", "/email/verify", Json.object("token", token), false, null));
    }

    /** Verifies the email with the emailed code; returns the user. */
    public PoolUser verifyEmailWithCode(String email, String code) {
        return userAnswer(call("POST", "/email/verify", Json.object("email", email, "code", code), false, null));
    }

    /** Sends the verification email again to the signed-in user. */
    public JsonNode resendVerification() {
        return call("POST", "/email/verify/send", Collections.emptyMap(), true, null);
    }

    // --- the signed-in user ------------------------------------------------------------------------------------------

    /** {@code GET /me}: the user with org, roles, linked providers; updates {@link #getCurrentUser()}. */
    public PoolUser me() {
        JsonNode user = call("GET", "/me", null, true, null);
        replaceUser(user);
        return Json.convert(user, PoolUser.class);
    }

    public PoolUser updateProfile(ProfileUpdate fields) {
        JsonNode user = call("PATCH", "/me", fields.toBody(), true, null);
        replaceUser(user);
        return Json.convert(user, PoolUser.class);
    }

    /** Changes the password: every session of the user ends, this one too (the local session is cleared). */
    public JsonNode changePassword(String currentPassword, String newPassword) {
        JsonNode out = call("POST", "/me/password", Json.object("current_password", currentPassword, "new_password", newPassword), true, null);
        clearSession();
        return out;
    }

    /** Starts a change of address: a code/link goes to the new address. */
    public JsonNode changeEmail(String newEmail) {
        return call("POST", "/me/email", Json.object("new_email", newEmail), true, null);
    }

    public PoolUser confirmEmailChangeWithCode(String code) {
        return userAnswer(call("POST", "/me/email/confirm", Json.object("code", code), true, null));
    }

    public PoolUser confirmEmailChangeWithToken(String token) {
        return userAnswer(call("POST", "/me/email/confirm", Json.object("token", token), true, null));
    }

    /**
     * A guest account becomes a real one (same id). The current access token keeps {@code anon: true} until the next
     * refresh ({@link #refresh()}).
     */
    public PoolUser upgradeAnonymous(String email, String password) {
        return userAnswer(call("POST", "/me/upgrade", Json.object("email", email, "password", password), true, null));
    }

    /** Deletes the account ({@code password} when the user has one, else null); the local session is cleared. */
    public JsonNode deleteAccount(String password) {
        JsonNode out = call("DELETE", "/me", Json.object("password", password), true, null);
        clearSession();
        return out;
    }

    public void signOut() {
        signOut(false);
    }

    /** Signs out: best-effort server call (revokes the refresh token / the session, or every session), always clears locally. */
    public void signOut(boolean everywhere) {
        Session cur = state;
        try {
            if (cur != null) {
                String bearer = fresh(cur) ? cur.accessToken : null;
                if (bearer == null && everywhere && cur.refreshToken != null) {
                    bearer = getAccessToken();
                }
                call("POST", "/signout", Json.object("refresh_token", cur.refreshToken, "everywhere", everywhere), false, bearer);
            }
        } catch (AppAuthException ignored) {
            // signed out locally anyway
        }
        clearSession();
    }

    // --- organizations (B2B pools) -----------------------------------------------------------------------------------

    public OrganizationList organizations() {
        return Json.convert(call("GET", "/orgs", null, true, null), OrganizationList.class);
    }

    /** Creates an organization (B2B pools with open creation); the user is its owner. */
    public Organization createOrganization(String name) {
        return Json.convert(call("POST", "/orgs", Json.object("name", name), true, null), Organization.class);
    }

    /** Switches the session to another organization: new tokens (single-flight with the refreshes). */
    public ActiveOrg switchOrganization(String orgId) {
        String bearer = getAccessToken();
        refreshLock.lock();
        try {
            Session cur = state;
            if (cur == null || cur.refreshToken == null) {
                throw notSignedIn();
            }
            JsonNode data = call("POST", "/orgs/switch", Json.object("org_id", orgId, "refresh_token", cur.refreshToken), true, bearer);
            saveTokens(data, cur.user);
            return getCurrentOrg();
        } finally {
            refreshLock.unlock();
        }
    }

    public MemberPage members(String orgId) {
        return members(orgId, "", 0, 50);
    }

    /** The members of an organization (owners and admins only). */
    public MemberPage members(String orgId, String q, int skip, int limit) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("q", q != null ? q : "");
        params.put("skip", String.valueOf(skip));
        params.put("limit", String.valueOf(limit));
        return Json.convert(call("GET", "/orgs/" + Util.encode(orgId) + "/members?" + Util.query(params), null, true, null), MemberPage.class);
    }

    /** Adds a member; the answer may include a temporary password to hand over. */
    public JsonNode addMember(String orgId, String email, String displayName, String password, List<String> roles) {
        return call("POST", "/orgs/" + Util.encode(orgId) + "/members", Json.object("email", email,
                "display_name", displayName != null ? displayName : "", "password", password,
                "roles", roles != null ? roles : Collections.emptyList()), true, null);
    }

    public JsonNode setMemberRoles(String orgId, String userId, List<String> roles) {
        return call("PATCH", "/orgs/" + Util.encode(orgId) + "/members/" + Util.encode(userId), Json.object("roles", roles), true, null);
    }

    public JsonNode removeMember(String orgId, String userId) {
        return call("DELETE", "/orgs/" + Util.encode(orgId) + "/members/" + Util.encode(userId), null, true, null);
    }

    // --- hosted sign-in (OpenID Connect, code + PKCE) ----------------------------------------------------------------

    /**
     * Builds the URL of the hosted sign-in page (fresh state, nonce, PKCE S256 verifier) and keeps the transaction in the
     * storage for {@link #handleRedirectCallback}. Open {@link AuthorizationRequest#getUrl()} in the system browser.
     */
    public AuthorizationRequest buildAuthorizationRequest(AuthorizationOptions options) {
        AuthorizationOptions o = options != null ? options : new AuthorizationOptions();
        String redirect = o.redirectUri != null ? o.redirectUri : redirectUri;
        if (redirect == null) {
            throw new IllegalStateException("buildAuthorizationRequest: a redirectUri is required (client option or AuthorizationOptions)");
        }
        AuthorizationRequest req = AuthorizationRequest.create(issuer, clientId, redirect, o);
        storage.set(pendingKey(), req.toJson());
        return req;
    }

    /**
     * Completes a hosted sign-in from the callback URL: checks {@code error}, {@code state} (constant time) and {@code iss},
     * exchanges the code (PKCE), checks the ID token's nonce, keeps the session and returns the user.
     */
    public PoolUser handleRedirectCallback(String callbackUrl) {
        Map<String, String> params = Util.queryParams(callbackUrl);
        AuthorizationRequest tx = AuthorizationRequest.fromJson(storage.get(pendingKey()));
        if (params.get("error") != null && tx != null && Util.constantTimeEquals(tx.getState(), params.get("state"))) {
            storage.remove(pendingKey());
        }
        String code = Http.checkCallback(params, tx, issuer);
        storage.remove(pendingKey());
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", tx.getRedirectUri());
        form.put("client_id", clientId);
        form.put("code_verifier", tx.getCodeVerifier());
        JsonNode data = Http.postForm(http, timeout, issuer + "/token", form,
                clientSecret != null ? Util.basicAuth(clientId, clientSecret) : null);
        String idToken = Json.text(data, "id_token");
        if (idToken != null) {
            JsonNode claims = Util.decodeJwtPayload(idToken);
            if (claims == null || !Util.constantTimeEquals(tx.getNonce(), Json.text(claims, "nonce"))) {
                throw new AppAuthException(400, "invalid_nonce", "Nonce mismatch");
            }
            if (!issuer.equals(Json.text(claims, "iss")) || !audienceContains(claims.get("aud"), clientId)) {
                throw new AppAuthException(400, "invalid_id_token", "ID token of another issuer or app");
            }
        }
        saveTokens(data, null);
        try {
            return me();
        } catch (AppAuthException e) {
            return getCurrentUser();
        }
    }

    /** The end-session URL of the hosted page (with the ID token as hint when there is one). */
    public String buildLogoutUrl(String postLogoutRedirectUri, String logoutState) {
        Session s = state;
        Map<String, String> params = new LinkedHashMap<>();
        params.put("client_id", clientId);
        params.put("id_token_hint", s != null ? s.idToken : null);
        params.put("post_logout_redirect_uri", postLogoutRedirectUri);
        params.put("state", logoutState);
        return issuer + "/logout?" + Util.query(params);
    }

    /**
     * Signs out locally and on the server ({@link #signOut(boolean)}) and returns the end-session URL to open in the
     * browser (ends the hosted page's browser session too).
     */
    public String signOutRedirect(String postLogoutRedirectUri, String logoutState) {
        String url = buildLogoutUrl(postLogoutRedirectUri, logoutState);
        signOut(false);
        return url;
    }

    // --- internals ---------------------------------------------------------------------------------------------------

    private String pendingKey() {
        return storageKey + ".pkce";
    }

    private static boolean audienceContains(JsonNode aud, String clientId) {
        if (aud == null) {
            return false;
        }
        if (aud.isTextual()) {
            return clientId.equals(aud.asText());
        }
        if (aud.isArray()) {
            for (JsonNode a : aud) {
                if (clientId.equals(a.asText())) {
                    return true;
                }
            }
        }
        return false;
    }

    private AppAuthException notSignedIn() {
        return new AppAuthException(401, "not_signed_in", "Not signed in");
    }

    private boolean fresh(Session s) {
        return s.accessToken != null && s.expiresAt - clock.millis() > SKEW_MS;
    }

    /**
     * A JSON API call. {@code signedIn}: a call that needs the user's token ({@code bearer}, or the current one); a 401
     * {@code token_*} then ends the local session. {@code invalid_refresh_token} always does.
     */
    private JsonNode call(String method, String path, Object body, boolean signedIn, String bearer) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(issuer + API + path))
                .timeout(timeout)
                .header("X-Client-Id", clientId)
                .header("Accept", "application/json");
        if (body != null) {
            b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(Json.write(body)));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        String token = bearer != null ? bearer : (signedIn ? getAccessToken() : null);
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> res = Http.send(http, b.build());
        JsonNode data = Json.parse(res.body());
        if (res.statusCode() < 200 || res.statusCode() >= 300) {
            AppAuthException e = AppAuthException.fromApi(res.statusCode(), data);
            if (e.getStatus() == 401 && ((signedIn && e.getCode().startsWith("token_")) || "invalid_refresh_token".equals(e.getCode()))) {
                clearSession();
            }
            throw e;
        }
        return data;
    }

    private AuthOutcome outcome(JsonNode data) {
        if ("ok".equals(Json.text(data, "status")) && Json.text(data, "access_token") != null) {
            saveTokens(data, null);
        }
        return AuthOutcome.of(data);
    }

    private void saveTokens(JsonNode data, JsonNode userFallback) {
        Session cur = state;
        JsonNode user = data.hasNonNull("user") ? data.get("user") : userFallback;
        String idToken = Json.text(data, "id_token");
        if (idToken == null && cur != null) {
            idToken = cur.idToken;
        }
        long expiresIn = data.path("expires_in").asLong(0);
        if (expiresIn <= 0) {
            expiresIn = 900;
        }
        JsonNode org = data.hasNonNull("org") ? data.get("org") : null;
        save(new Session(Json.text(data, "access_token"), Json.text(data, "refresh_token"), idToken,
                clock.millis() + expiresIn * 1000L, user, org));
    }

    private PoolUser userAnswer(JsonNode data) {
        JsonNode user = data.get("user");
        Session cur = state;
        if (user != null && user.isObject() && cur != null && cur.user != null
                && Objects.equals(Json.text(cur.user, "id"), Json.text(user, "id"))) {
            replaceUser(user);
        }
        return Json.convert(user, PoolUser.class);
    }

    private void replaceUser(JsonNode user) {
        Session cur = state;
        if (cur != null && user != null && user.isObject()) {
            save(new Session(cur.accessToken, cur.refreshToken, cur.idToken, cur.expiresAt, user, cur.org));
        }
    }

    private void clearSession() {
        if (state == null) {
            storage.remove(storageKey);    // already signed out: nothing to tell the listeners
            return;
        }
        save(null);
    }

    private Session load() {
        try {
            JsonNode n = Json.parse(storage.get(storageKey));
            if (!n.isObject() || Json.text(n, "refreshToken") == null) {
                return null;
            }
            return new Session(Json.text(n, "accessToken"), Json.text(n, "refreshToken"), Json.text(n, "idToken"),
                    n.path("expiresAt").asLong(0), n.hasNonNull("user") ? n.get("user") : null, n.hasNonNull("org") ? n.get("org") : null);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void save(Session next) {
        synchronized (this) {
            state = next;
            if (next != null && next.refreshToken != null) {
                storage.set(storageKey, next.toJson());
            } else {
                storage.remove(storageKey);
            }
        }
        PoolUser user = getCurrentUser();
        ActiveOrg org = getCurrentOrg();
        for (AuthStateListener l : listeners) {
            safeNotify(l, user, org);
        }
    }

    private static void safeNotify(AuthStateListener listener, PoolUser user, ActiveOrg org) {
        try {
            listener.onAuthStateChanged(user, org);
        } catch (RuntimeException ignored) {
            // a listener's error is its own
        }
    }

    /** The stored session: {@code {accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}}. */
    static final class Session {
        final String accessToken;
        final String refreshToken;
        final String idToken;
        final long expiresAt;
        final JsonNode user;
        final JsonNode org;
        private volatile PoolUser typedUser;
        private volatile ActiveOrg typedOrg;

        Session(String accessToken, String refreshToken, String idToken, long expiresAt, JsonNode user, JsonNode org) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.idToken = idToken;
            this.expiresAt = expiresAt;
            this.user = user;
            this.org = org;
        }

        PoolUser typedUser() {
            if (typedUser == null && user != null) {
                typedUser = Json.convert(user, PoolUser.class);
            }
            return typedUser;
        }

        ActiveOrg typedOrg() {
            if (typedOrg == null && org != null) {
                typedOrg = Json.convert(org, ActiveOrg.class);
            }
            return typedOrg;
        }

        String toJson() {
            ObjectNode n = Json.MAPPER.createObjectNode();
            n.put("accessToken", accessToken);
            n.put("refreshToken", refreshToken);
            n.put("idToken", idToken);
            n.put("expiresAt", expiresAt);
            n.set("user", user);
            n.set("org", org);
            return n.toString();
        }
    }

    private static final class DefaultExecutor {
        static final ExecutorService INSTANCE = Executors.newCachedThreadPool(new java.util.concurrent.ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger();

            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "openback-app-auth-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
    }

    /** Options of {@link AppAuthClient}. */
    public static final class Builder {
        private final String issuer;
        private final String clientId;
        private String redirectUri;
        private TokenStorage storage;
        private String storageKey;
        private HttpClient httpClient;
        private String clientSecret;
        private Duration timeout;
        private Clock clock;
        private Executor executor;

        private Builder(String issuer, String clientId) {
            this.issuer = issuer;
            this.clientId = clientId;
        }

        /** The default redirect URI of the hosted sign-in (registered in the app). */
        public Builder redirectUri(String value) {
            this.redirectUri = value;
            return this;
        }

        /** Where the session is kept (default: in memory). */
        public Builder storage(TokenStorage value) {
            this.storage = value;
            return this;
        }

        /** Default {@code openback.auth.<clientId>}. */
        public Builder storageKey(String value) {
            this.storageKey = value;
            return this;
        }

        /** Your {@link HttpClient} (proxy, TLS, timeouts). */
        public Builder httpClient(HttpClient value) {
            this.httpClient = value;
            return this;
        }

        /**
         * Confidential apps only (kind {@code web}/{@code backend}): sent with {@code client_secret_basic} on the code
         * exchange. Never put a secret in a desktop or mobile app.
         */
        public Builder clientSecret(String value) {
            this.clientSecret = value;
            return this;
        }

        /** Per-request timeout (default 30 s). */
        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        /** The clock (tests). */
        public Builder clock(Clock value) {
            this.clock = value;
            return this;
        }

        /** The executor of the async variants (default: a cached pool of daemon threads). */
        public Builder executor(Executor value) {
            this.executor = value;
            return this;
        }

        public AppAuthClient build() {
            return new AppAuthClient(this);
        }
    }
}
