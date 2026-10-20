package io.openback.appauth.android

import java.util.concurrent.ConcurrentHashMap

/**
 * Where [OpenBackAuth] keeps its session: strings by key. The session is a JSON document
 * `{accessToken, refreshToken, idToken, expiresAt, user, org}` under `openback.auth.<clientId>`; a pending hosted sign-in
 * (state, nonce, PKCE verifier) under `openback.auth.<clientId>.pkce`.
 *
 * The default on Android is [KeystoreTokenStorage] ([OpenBackAuth.create]). Implementations must be thread-safe and write
 * synchronously (the refresh token rotates at every use: losing the new one ends the session). The methods are called
 * from the SDK's IO dispatcher. The values are secrets: never log them.
 */
public interface TokenStorage {
    public fun get(key: String): String?
    public fun set(key: String, value: String)
    public fun remove(key: String)
}

/** A [TokenStorage] in memory (lost when the process ends): tests, or apps that never keep a session. */
public class InMemoryTokenStorage : TokenStorage {
    private val data = ConcurrentHashMap<String, String>()
    override fun get(key: String): String? = data[key]
    override fun set(key: String, value: String) {
        data[key] = value
    }
    override fun remove(key: String) {
        data.remove(key)
    }
}
