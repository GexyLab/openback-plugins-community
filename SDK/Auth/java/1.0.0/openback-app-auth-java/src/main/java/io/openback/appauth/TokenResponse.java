package io.openback.appauth;

/**
 * Tokens answered by {@code POST <issuer>/token} or {@code POST /api/v1/token/refresh}. The refresh token ROTATES:
 * store the new one atomically and drop the old one. {@link #toString()} never prints the tokens.
 */
public final class TokenResponse {
    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String scope;
    private String refreshToken;
    private long refreshExpiresIn;
    private String idToken;
    private ActiveOrg org;

    public String getAccessToken() {
        return accessToken;
    }

    /** "Bearer". */
    public String getTokenType() {
        return tokenType;
    }

    /** Seconds. */
    public long getExpiresIn() {
        return expiresIn;
    }

    public String getScope() {
        return scope;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    /** Seconds. */
    public long getRefreshExpiresIn() {
        return refreshExpiresIn;
    }

    /** Only on the authorization-code exchange with scope openid (never on refresh). */
    public String getIdToken() {
        return idToken;
    }

    /** The active organization (B2B pools), else null. */
    public ActiveOrg getOrg() {
        return org;
    }

    @Override
    public String toString() {
        return "TokenResponse{tokenType=" + tokenType + ", expiresIn=" + expiresIn + ", scope=" + scope + ", tokens=***}";
    }
}
