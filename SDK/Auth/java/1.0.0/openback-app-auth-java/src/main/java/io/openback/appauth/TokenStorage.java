package io.openback.appauth;

/**
 * Where {@link AppAuthClient} keeps its session: strings by key. The session is a JSON document
 * {@code {accessToken, refreshToken, idToken, expiresAt, user, org}} under {@code openback.auth.<clientId>}; the pending
 * hosted sign-in (state, nonce, PKCE verifier) under {@code openback.auth.<clientId>.pkce}.
 *
 * <p>The default is {@link InMemoryTokenStorage}. A desktop app or a server keeping a user's session across restarts
 * plugs its own: an encrypted file, a database row, the HTTP session of the signed-in visitor. Implementations must be
 * thread-safe and should write atomically (the refresh token rotates at every use: losing the new one ends the session).
 * The values are secrets: never log them.
 */
public interface TokenStorage {
    /** The value under {@code key}, or null. */
    String get(String key);

    /** Stores {@code value} under {@code key}, replacing any previous value. */
    void set(String key, String value);

    /** Removes {@code key} (no error if absent). */
    void remove(String key);
}
