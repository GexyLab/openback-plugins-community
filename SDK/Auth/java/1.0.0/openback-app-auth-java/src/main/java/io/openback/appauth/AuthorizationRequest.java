package io.openback.appauth;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A hosted sign-in in progress: the URL to open and the transaction to check the callback with (state, nonce, PKCE
 * verifier, redirect URI). {@link AppAuthClient} keeps it in its storage; a web app ({@link OidcWebClient}) keeps it in
 * the visitor's server-side session ({@link #toJson()} / {@link #fromJson(String)}, or Java serialization).
 * The values are secrets: never log them or put them in a cookie readable by scripts.
 */
public final class AuthorizationRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String url;
    private final String state;
    private final String nonce;
    private final String codeVerifier;
    private final String redirectUri;

    public AuthorizationRequest(String url, String state, String nonce, String codeVerifier, String redirectUri) {
        this.url = url;
        this.state = state;
        this.nonce = nonce;
        this.codeVerifier = codeVerifier;
        this.redirectUri = redirectUri;
    }

    /** Builds a request: fresh state, nonce and PKCE verifier from the CSPRNG. */
    static AuthorizationRequest create(String issuer, String clientId, String redirectUri, AuthorizationOptions options) {
        AuthorizationOptions o = options != null ? options : new AuthorizationOptions();
        String verifier = Util.codeVerifier();
        String state = Util.randomString(24);
        String nonce = Util.randomString(24);
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("scope", o.scope != null && !o.scope.isBlank() ? o.scope : "openid profile email");
        params.put("state", state);
        params.put("nonce", nonce);
        params.put("code_challenge", Util.codeChallenge(verifier));
        params.put("code_challenge_method", "S256");
        params.put("provider", o.provider);
        params.put("org_id", o.orgId);
        params.put("prompt", o.prompt);
        params.put("screen_hint", o.screenHint);
        params.put("login_hint", o.loginHint);
        params.put("max_age", o.maxAge != null ? String.valueOf(o.maxAge) : null);
        params.put("ui_locales", o.uiLocales);
        return new AuthorizationRequest(issuer + "/authorize?" + Util.query(params), state, nonce, verifier, redirectUri);
    }

    /** The URL to open in the browser. */
    public String getUrl() {
        return url;
    }

    public String getState() {
        return state;
    }

    public String getNonce() {
        return nonce;
    }

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    /** JSON {@code {state, nonce, codeVerifier, redirectUri, url}} for a server-side session store. */
    public String toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("state", state);
        m.put("nonce", nonce);
        m.put("codeVerifier", codeVerifier);
        m.put("redirectUri", redirectUri);
        m.put("url", url);
        return Json.write(m);
    }

    /** Reads {@link #toJson()}; null if the text is not such a document. */
    public static AuthorizationRequest fromJson(String json) {
        JsonNode n = Json.parse(json);
        if (!n.isObject() || Json.text(n, "state") == null || Json.text(n, "codeVerifier") == null) {
            return null;
        }
        return new AuthorizationRequest(Json.text(n, "url"), Json.text(n, "state"), Json.text(n, "nonce"),
                Json.text(n, "codeVerifier"), Json.text(n, "redirectUri"));
    }

    @Override
    public String toString() {
        return "AuthorizationRequest{redirectUri=" + redirectUri + ", secrets=***}";
    }
}
