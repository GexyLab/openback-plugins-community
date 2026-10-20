package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OpenID Connect for a {@code web} app (a server with a client secret): hosted sign-in with code + PKCE + nonce, the ID
 * token verified with the pool's keys.
 *
 * <pre>{@code
 * OidcWebClient oidc = OidcWebClient.builder(issuer, "uapp_...", secret, "https://app.example.com/callback").build();
 * // /login
 * AuthorizationRequest tx = oidc.authorizationUrl(new AuthorizationOptions());
 * session.setAttribute("oidc", tx.toJson());           // server-side session
 * response.sendRedirect(tx.getUrl());
 * // /callback
 * OidcWebClient.Result r = oidc.handleCallback(queryParams, AuthorizationRequest.fromJson((String) session.getAttribute("oidc")));
 * }</pre>
 *
 * Client authentication: {@code client_secret_basic} (default) or {@code client_secret_post}.
 */
public final class OidcWebClient {
    /** How the client authenticates at {@code /token} and {@code /revoke}. */
    public enum ClientAuthMethod { CLIENT_SECRET_BASIC, CLIENT_SECRET_POST }

    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final ClientAuthMethod authMethod;
    private final HttpClient http;
    private final Duration timeout;
    private final TokenVerifier verifier;

    private OidcWebClient(Builder b) {
        this.issuer = Util.normalizeIssuer(b.issuer);
        if (b.clientId == null || b.clientSecret == null) {
            throw new IllegalArgumentException("OidcWebClient: clientId and clientSecret are required");
        }
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.redirectUri = b.redirectUri;
        this.authMethod = b.authMethod;
        this.http = b.httpClient != null ? b.httpClient : Http.defaultClient();
        this.timeout = b.timeout;
        this.verifier = b.verifier != null ? b.verifier
                : TokenVerifier.builder(issuer).clientIds(clientId).httpClient(this.http).build();
    }

    public static Builder builder(String issuer, String clientId, String clientSecret, String redirectUri) {
        return new Builder(issuer, clientId, clientSecret, redirectUri);
    }

    /** The verifier of the pool's tokens (also usable for your API's access tokens). */
    public TokenVerifier getVerifier() {
        return verifier;
    }

    /**
     * The hosted sign-in URL and its transaction (state, nonce, PKCE verifier, redirect URI): store the transaction in the
     * visitor's server-side session, redirect to {@link AuthorizationRequest#getUrl()}.
     */
    public AuthorizationRequest authorizationUrl(AuthorizationOptions options) {
        AuthorizationOptions o = options != null ? options : new AuthorizationOptions();
        String redirect = o.redirectUri != null ? o.redirectUri : redirectUri;
        if (redirect == null) {
            throw new IllegalStateException("authorizationUrl: a redirectUri is required");
        }
        return AuthorizationRequest.create(issuer, clientId, redirect, o);
    }

    /**
     * Completes the sign-in: checks {@code error}, {@code state} (constant time) and {@code iss}, exchanges the code with
     * the PKCE verifier and the client secret, verifies the ID token (signature, iss, aud, exp, nonce).
     *
     * @param params      the callback's query parameters
     * @param transaction the transaction stored by {@link #authorizationUrl} (remove it from the session: one use)
     */
    public Result handleCallback(Map<String, String> params, AuthorizationRequest transaction) {
        String code = Http.checkCallback(params, transaction, issuer);
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", transaction.getRedirectUri());
        form.put("code_verifier", transaction.getCodeVerifier());
        TokenResponse tokens = Json.convert(postToken("/token", form), TokenResponse.class);
        Map<String, Object> idClaims = Collections.emptyMap();
        if (tokens.getIdToken() != null) {
            idClaims = verifier.verifyIdToken(tokens.getIdToken(), transaction.getNonce());
        }
        return new Result(tokens, idClaims);
    }

    /** {@link #handleCallback(Map, AuthorizationRequest)} from the full callback URL. */
    public Result handleCallback(String callbackUrl, AuthorizationRequest transaction) {
        return handleCallback(Util.queryParams(callbackUrl), transaction);
    }

    /** Renews the tokens. The refresh token ROTATES: store the new one and drop the old one. */
    public TokenResponse refresh(String refreshToken) {
        return refresh(refreshToken, null);
    }

    /** Renews the tokens, optionally for another organization (B2B). */
    public TokenResponse refresh(String refreshToken, String orgId) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        form.put("org_id", orgId);
        return Json.convert(postToken("/token", form), TokenResponse.class);
    }

    /** Revokes a refresh token (RFC 7009); the session it belongs to cannot be renewed any more. */
    public void revoke(String refreshToken) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", refreshToken);
        form.put("token_type_hint", "refresh_token");
        postToken("/revoke", form);
    }

    /** {@code GET /userinfo}: {@code sub, email, email_verified, name, picture, locale, org_id, roles, attributes}. */
    public JsonNode userinfo(String accessToken) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(issuer + "/userinfo")).timeout(timeout)
                .header("Authorization", "Bearer " + accessToken).header("Accept", "application/json").GET().build();
        HttpResponse<String> res = Http.send(http, req);
        JsonNode data = Json.parse(res.body());
        if (res.statusCode() != 200) {
            throw AppAuthException.fromOAuth(res.statusCode(), data);
        }
        return data;
    }

    /** The end-session URL: {@code <issuer>/logout?client_id&id_token_hint&post_logout_redirect_uri&state}. */
    public String logoutUrl(String idTokenHint, String postLogoutRedirectUri, String state) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("client_id", clientId);
        params.put("id_token_hint", idTokenHint);
        params.put("post_logout_redirect_uri", postLogoutRedirectUri);
        params.put("state", state);
        return issuer + "/logout?" + Util.query(params);
    }

    private JsonNode postToken(String path, Map<String, String> form) {
        Map<String, String> body = new LinkedHashMap<>(form);
        String authorization = null;
        if (authMethod == ClientAuthMethod.CLIENT_SECRET_POST) {
            body.put("client_id", clientId);
            body.put("client_secret", clientSecret);
        } else {
            body.put("client_id", clientId);
            authorization = Util.basicAuth(clientId, clientSecret);
        }
        return Http.postForm(http, timeout, issuer + path, body, authorization);
    }

    /** The tokens of a completed sign-in and the verified ID token's claims. */
    public static final class Result {
        private final TokenResponse tokens;
        private final Map<String, Object> idTokenClaims;

        Result(TokenResponse tokens, Map<String, Object> idTokenClaims) {
            this.tokens = tokens;
            this.idTokenClaims = idTokenClaims;
        }

        public TokenResponse getTokens() {
            return tokens;
        }

        /** iss, sub, aud, exp, auth_time, sid, pool, email, email_verified, name, picture, org_id, roles, amr, nonce. */
        public Map<String, Object> getIdTokenClaims() {
            return idTokenClaims;
        }

        /** The user id ({@code sub}). */
        public String getUserId() {
            Object sub = idTokenClaims.get("sub");
            return sub == null ? null : sub.toString();
        }
    }

    /** Options of {@link OidcWebClient}. */
    public static final class Builder {
        private final String issuer;
        private final String clientId;
        private final String clientSecret;
        private final String redirectUri;
        private ClientAuthMethod authMethod = ClientAuthMethod.CLIENT_SECRET_BASIC;
        private HttpClient httpClient;
        private Duration timeout = Http.DEFAULT_TIMEOUT;
        private TokenVerifier verifier;

        private Builder(String issuer, String clientId, String clientSecret, String redirectUri) {
            this.issuer = issuer;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.redirectUri = redirectUri;
        }

        public Builder clientAuthMethod(ClientAuthMethod value) {
            this.authMethod = value;
            return this;
        }

        public Builder httpClient(HttpClient value) {
            this.httpClient = value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        /** A verifier of your own (e.g. shared, or with more client IDs). */
        public Builder verifier(TokenVerifier value) {
            this.verifier = value;
            return this;
        }

        public OidcWebClient build() {
            return new OidcWebClient(this);
        }
    }
}
