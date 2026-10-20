package io.openback.appauth.android

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Options of a hosted sign-in (`<issuer>/authorize`). All optional. */
public data class AuthorizationOptions(
    /** Default: the client's redirect URI. Must match a registered one exactly. */
    val redirectUri: String? = null,
    val scope: String = "openid profile email",
    /** A provider id (`uprov_...`): straight to Google, Microsoft... */
    val provider: String? = null,
    /** B2B: the organization to sign in to. */
    val orgId: String? = null,
    /** `none` or `login`. */
    val prompt: String? = null,
    /** `signup`: open the sign-up form. */
    val screenHint: String? = null,
    val loginHint: String? = null,
    val maxAge: Int? = null,
    /** `it` or `en`. */
    val uiLocales: String? = null,
)

/**
 * A hosted sign-in in progress: the [url] to open in a Custom Tab and the transaction the callback is checked against.
 * [OpenBackAuth] keeps it in its storage until the callback. The values are secrets: never log them.
 */
@Serializable
public data class AuthorizationRequest(
    val url: String,
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectUri: String,
) {
    override fun toString(): String = "AuthorizationRequest(redirectUri=$redirectUri, secrets=***)"

    internal fun toJson(): String = JSON.encodeToString(this)

    internal companion object {
        private val JSON = Json { ignoreUnknownKeys = true }

        fun fromJson(text: String?): AuthorizationRequest? = try {
            text?.let { JSON.decodeFromString(serializer(), it) }
        } catch (e: Exception) {
            null
        }

        fun create(issuer: String, clientId: String, redirectUri: String, o: AuthorizationOptions): AuthorizationRequest {
            val verifier = AuthCrypto.codeVerifier()
            val state = AuthCrypto.randomString(24)
            val nonce = AuthCrypto.randomString(24)
            val params = linkedMapOf(
                "response_type" to "code",
                "client_id" to clientId,
                "redirect_uri" to redirectUri,
                "scope" to o.scope.ifBlank { "openid profile email" },
                "state" to state,
                "nonce" to nonce,
                "code_challenge" to AuthCrypto.codeChallenge(verifier),
                "code_challenge_method" to "S256",
                "provider" to o.provider,
                "org_id" to o.orgId,
                "prompt" to o.prompt,
                "screen_hint" to o.screenHint,
                "login_hint" to o.loginHint,
                "max_age" to o.maxAge?.toString(),
                "ui_locales" to o.uiLocales,
            )
            return AuthorizationRequest("$issuer/authorize?${AuthCrypto.query(params)}", state, nonce, verifier, redirectUri)
        }
    }
}
