package io.openback.appauth.android

import kotlinx.serialization.json.JsonElement

/**
 * An error answered by the user pool, or a local failure of the SDK.
 *
 * - [status]: the HTTP status (0 for a network or local failure);
 * - [code]: the service's code (`invalid_credentials`, `weak_password`, `token_expired`...), an OAuth error at `/token`
 *   (`invalid_grant`...), `http_<status>` when the answer has none, or a local code: `network_error`, `not_signed_in`,
 *   `invalid_state`, `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `no_pending_request`, `invalid_request`;
 * - [detail]: the raw `detail` of the answer (for `weak_password`: `detail.problems`).
 */
public class AuthException(
    public val status: Int,
    public val code: String,
    message: String?,
    public val detail: JsonElement? = null,
    cause: Throwable? = null,
) : Exception(if (message.isNullOrEmpty()) code else message, cause) {

    /** True when the error means the local session is dead (401 `token_*` or `invalid_refresh_token`). */
    public val isSessionEnded: Boolean
        get() = status == 401 && (code.startsWith("token_") || code == "invalid_refresh_token")

    override fun toString(): String = "AuthException(status=$status, code=$code, message=$message)"
}
