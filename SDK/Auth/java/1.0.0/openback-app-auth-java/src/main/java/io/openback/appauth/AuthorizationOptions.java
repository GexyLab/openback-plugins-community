package io.openback.appauth;

/**
 * Options of a hosted sign-in ({@code <issuer>/authorize}). All optional; fluent setters.
 *
 * <pre>{@code new AuthorizationOptions().provider("uprov_google").uiLocales("en")}</pre>
 */
public final class AuthorizationOptions {
    String redirectUri;
    String scope = "openid profile email";
    String provider;
    String orgId;
    String prompt;
    String screenHint;
    String loginHint;
    Integer maxAge;
    String uiLocales;

    /** The redirect URI (default: the client's). Must match a registered one exactly. */
    public AuthorizationOptions redirectUri(String value) {
        this.redirectUri = value;
        return this;
    }

    /** Default {@code "openid profile email"}. */
    public AuthorizationOptions scope(String value) {
        this.scope = value;
        return this;
    }

    /** A provider id ({@code uprov_...}): go straight to Google, Microsoft... */
    public AuthorizationOptions provider(String value) {
        this.provider = value;
        return this;
    }

    /** B2B: the organization to sign in to. */
    public AuthorizationOptions orgId(String value) {
        this.orgId = value;
        return this;
    }

    /** {@code "none"} (no UI: {@code login_required} without a session) or {@code "login"} (always ask). */
    public AuthorizationOptions prompt(String value) {
        this.prompt = value;
        return this;
    }

    /** {@code "signup"}: open the sign-up form. */
    public AuthorizationOptions screenHint(String value) {
        this.screenHint = value;
        return this;
    }

    /** Pre-fills the email. */
    public AuthorizationOptions loginHint(String value) {
        this.loginHint = value;
        return this;
    }

    /** Seconds since the last authentication after which the user must sign in again. */
    public AuthorizationOptions maxAge(Integer value) {
        this.maxAge = value;
        return this;
    }

    /** {@code "it"} or {@code "en"}. */
    public AuthorizationOptions uiLocales(String value) {
        this.uiLocales = value;
        return this;
    }
}
