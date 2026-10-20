package io.openback.appauth.android

import android.content.Context
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The client of an OpenBack user pool ("App authenticator") for Android apps.
 *
 * Two ways to sign users in, freely mixed: your own screens through the pool's JSON API ([signInWithPassword],
 * [signUp], [signInWithEmailCode], [signInAnonymously], [verifyMfa]...), or the pool's hosted sign-in page in a Custom
 * Tab ([buildAuthorizationRequest] + [OpenBackSignInContract] + [handleRedirectCallback]).
 *
 * The session lives in a [TokenStorage] ([KeystoreTokenStorage] with [create]). [getAccessToken] renews the access
 * token when it expires in less than 60 seconds, ONE refresh at a time (refresh tokens rotate at every use), and the
 * refresh is never cancelled half-way. [authState] tells the UI who is signed in.
 *
 * ```
 * val auth = OpenBackAuth.create(context, "https://api.example.com/gateway/shop/auth/main", "uapp_...",
 *     redirectUri = "com.example.app:/oauth2redirect")
 * when (val res = auth.signInWithPassword(email, password)) {
 *     is AuthOutcome.SignedIn -> ...
 *     is AuthOutcome.MfaRequired -> auth.verifyMfa(res.mfaToken, code)
 *     else -> ...
 * }
 * ```
 */
public class OpenBackAuth(
    issuer: String,
    public val clientId: String,
    options: Options = Options(),
) {
    /** Options of the client. */
    public data class Options(
        /** The default redirect URI of the hosted sign-in, e.g. `com.example.app:/oauth2redirect`. */
        val redirectUri: String? = null,
        /** Default: in memory ([create] uses [KeystoreTokenStorage]). */
        val storage: TokenStorage? = null,
        /** Default `openback.auth.<clientId>`. */
        val storageKey: String? = null,
        /** Your OkHttpClient (timeouts, proxy, certificate pinning). Do NOT add [OpenBackAuthInterceptor] to it. */
        val httpClient: OkHttpClient? = null,
        /** Never in a mobile app: only for confidential clients (kept for parity with the server SDKs). */
        val clientSecret: String? = null,
        val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        val clock: () -> Long = { System.currentTimeMillis() },
    )

    public companion object {
        /** Renew the access token when it expires within this many milliseconds. */
        public const val SKEW_MS: Long = 60_000L
        private const val API = "/api/v1"
        private val JSON_TYPE = "application/json".toMediaType()

        /** A client whose session is encrypted with an Android Keystore key ([KeystoreTokenStorage]). */
        @JvmStatic
        @JvmOverloads
        public fun create(
            context: Context,
            issuer: String,
            clientId: String,
            redirectUri: String? = null,
            httpClient: OkHttpClient? = null,
        ): OpenBackAuth = OpenBackAuth(
            issuer, clientId,
            Options(redirectUri = redirectUri, storage = KeystoreTokenStorage(context.applicationContext), httpClient = httpClient),
        )

        internal val json: Json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            coerceInputValues = true
        }
    }

    /** The pool's address (trailing slash removed). */
    public val issuer: String = issuer.trim().trimEnd('/').also {
        require(it.isNotEmpty()) { "issuer is required" }
        require(clientId.isNotBlank()) { "clientId is required" }
    }

    private val redirectUri = options.redirectUri
    private val clientSecret = options.clientSecret
    private val storage: TokenStorage = options.storage ?: InMemoryTokenStorage()
    private val storageKey: String = options.storageKey ?: "openback.auth.$clientId"
    private val pendingKey: String get() = "$storageKey.pkce"
    // OkHttp silently retries a request after some connection failures: never for these calls (a replayed refresh
    // would present a rotated refresh token and revoke the session). newBuilder() shares the app's pool and dispatcher.
    private val http: OkHttpClient = (options.httpClient?.newBuilder() ?: OkHttpClient.Builder())
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .build()
    private val io = options.ioDispatcher
    private val clock = options.clock
    private val refreshMutex = Mutex()
    private val listeners = CopyOnWriteArrayList<(PoolUser?, ActiveOrg?) -> Unit>()

    @Volatile
    private var session: Session? = load()
    private val _authState = MutableStateFlow(stateOf(session))

    /** Who is signed in; collect it from the UI. */
    public val authState: StateFlow<AuthState> = _authState.asStateFlow()

    /** The signed-in user (as last read), or null. */
    public val currentUser: PoolUser? get() = session?.typedUser()

    /** The active organization (B2B), or null. */
    public val currentOrg: ActiveOrg? get() = session?.typedOrg()

    /** The access token's claims, decoded but NOT verified (display only). */
    public val accessTokenClaims: JsonObject? get() = AuthCrypto.decodeJwtPayload(session?.accessToken, json)

    /** True when a session is kept. */
    public val isSignedIn: Boolean get() = session.let { it != null && (it.refreshToken != null || fresh(it)) }

    /** Listener of sign-ins/sign-outs: called immediately, then at every change. Returns the unsubscribe function. */
    public fun onAuthStateChanged(listener: (PoolUser?, ActiveOrg?) -> Unit): () -> Unit {
        listeners.add(listener)
        runCatching { listener(currentUser, currentOrg) }
        return { listeners.remove(listener) }
    }

    // --- tokens ------------------------------------------------------------------------------------------------------

    /**
     * A valid access token: the stored one if it expires in more than 60 seconds, else a refreshed one (single-flight).
     * @throws AuthException `not_signed_in`, `invalid_refresh_token` (session ended: cleared), `network_error`
     */
    public suspend fun getAccessToken(): String {
        val s = session
        if (s != null && fresh(s)) return s.accessToken!!
        return refresh(null)
    }

    /**
     * Renews the tokens now (optionally for another organization). One refresh at a time: callers that waited for a
     * refresh in progress get its result. The request is not cancelled with the caller (the rotated token must be kept),
     * and it is never retried after a network error.
     */
    public suspend fun refresh(orgId: String? = null): String {
        val before = session
        if (before?.refreshToken == null) throw notSignedIn()
        return refreshMutex.withLock {
            withContext(NonCancellable) {
                var cur = session ?: throw notSignedIn()
                val rt = cur.refreshToken ?: throw notSignedIn()
                if (orgId == null && rt != before.refreshToken && fresh(cur)) return@withContext cur.accessToken!!
                val stored = withContext(io) { load() }       // another client on the same storage may have rotated it
                if (stored?.refreshToken != null && stored.refreshToken != rt) {
                    session = stored
                    cur = stored
                    if (orgId == null && fresh(cur)) return@withContext cur.accessToken!!
                }
                val body = obj("refresh_token" to cur.refreshToken, "org_id" to orgId)
                val data = try {
                    call("POST", listOf("token", "refresh"), body, signedIn = false)
                } catch (e: AuthException) {
                    if (e.status == 401) clearSession()
                    throw e
                }
                saveTokens(data as JsonObject, cur.user)
                session!!.accessToken!!
            }
        }
    }

    // --- pool --------------------------------------------------------------------------------------------------------

    /** `GET /config`: methods, providers (`start_url`), password policy, mode, branding. */
    public suspend fun config(): JsonObject = call("GET", listOf("config"), null, false) as JsonObject

    // --- sign-up and sign-in -----------------------------------------------------------------------------------------

    public suspend fun signUp(email: String, password: String, displayName: String? = null, locale: String? = null, orgId: String? = null): AuthOutcome =
        outcome(call("POST", listOf("signup"), obj("email" to email, "password" to password, "display_name" to (displayName ?: ""),
            "locale" to locale, "org_id" to orgId), false))

    public suspend fun signInWithPassword(email: String, password: String, orgId: String? = null): AuthOutcome =
        outcome(call("POST", listOf("signin", "password"), obj("email" to email, "password" to password, "org_id" to orgId), false))

    /** Sends a one-time sign-in code. Always answers `{status: "sent"}`. */
    public suspend fun sendEmailCode(email: String): JsonObject =
        call("POST", listOf("signin", "email-code"), obj("email" to email), false) as JsonObject

    public suspend fun signInWithEmailCode(email: String, code: String, orgId: String? = null): AuthOutcome =
        outcome(call("POST", listOf("signin", "email-code", "verify"), obj("email" to email, "code" to code, "org_id" to orgId), false))

    /** With the token of an emailed sign-in link. */
    public suspend fun signInWithEmailLinkToken(token: String, orgId: String? = null): AuthOutcome =
        outcome(call("POST", listOf("signin", "email-code", "verify"), obj("token" to token, "org_id" to orgId), false))

    public suspend fun signInAnonymously(): AuthOutcome = outcome(call("POST", listOf("signin", "anonymous"), null, false))

    /** Second step: the authenticator code or a recovery code. */
    public suspend fun verifyMfa(mfaToken: String, code: String): AuthOutcome =
        outcome(call("POST", listOf("signin", "mfa"), obj("mfa_token" to mfaToken, "code" to code), false))

    /** Starts TOTP enrollment: signed in (no [mfaToken]) or during a sign-in (`MfaEnrollRequired`). */
    public suspend fun enrollMfa(mfaToken: String? = null): MfaEnrollment {
        val data = if (mfaToken != null) call("POST", listOf("mfa", "enroll"), obj("mfa_token" to mfaToken), false)
        else call("POST", listOf("mfa", "enroll"), JsonObject(emptyMap()), true)
        return json.decodeFromJsonElement(data)
    }

    /** Confirms the enrollment with a first code; with [mfaToken] it also completes the sign-in. */
    public suspend fun confirmMfa(code: String, mfaToken: String? = null): MfaConfirmation {
        if (mfaToken == null) {
            val data = call("POST", listOf("mfa", "enroll", "confirm"), obj("code" to code), true) as JsonObject
            return MfaConfirmation(recoveryCodes(data), null)
        }
        val data = call("POST", listOf("mfa", "enroll", "confirm"), obj("mfa_token" to mfaToken, "code" to code), false) as JsonObject
        return MfaConfirmation(recoveryCodes(data), outcome(data))
    }

    public suspend fun disableMfa(code: String): JsonObject =
        call("POST", listOf("mfa", "disable"), obj("code" to code), true) as JsonObject

    // --- passwords and emails ----------------------------------------------------------------------------------------

    /** Always answers `{status: "sent"}`. */
    public suspend fun sendPasswordReset(email: String): JsonObject =
        call("POST", listOf("password", "forgot"), obj("email" to email), false) as JsonObject

    /** With the reset link's [token], or the emailed [email] + [code]. */
    public suspend fun resetPassword(newPassword: String, token: String? = null, email: String? = null, code: String? = null): JsonObject =
        call("POST", listOf("password", "reset"), obj("token" to token, "email" to email, "code" to code, "new_password" to newPassword), false) as JsonObject

    /** Continues [AuthOutcome.PasswordChangeRequired]; then sign in again. */
    public suspend fun changeForcedPassword(changeToken: String, newPassword: String): JsonObject =
        call("POST", listOf("password", "reset"), obj("change_token" to changeToken, "new_password" to newPassword), false) as JsonObject

    /** With the verification link's [token], or [email] + [code]. Returns the user. */
    public suspend fun verifyEmail(token: String? = null, email: String? = null, code: String? = null): PoolUser? =
        userAnswer(call("POST", listOf("email", "verify"), obj("token" to token, "email" to email, "code" to code), false) as JsonObject)

    public suspend fun resendVerification(): JsonObject =
        call("POST", listOf("email", "verify", "send"), JsonObject(emptyMap()), true) as JsonObject

    // --- the signed-in user ------------------------------------------------------------------------------------------

    /** `GET /me` (with org, roles, providers); updates [currentUser]. */
    public suspend fun me(): PoolUser {
        val user = call("GET", listOf("me"), null, true) as JsonObject
        replaceUser(user)
        return json.decodeFromJsonElement(user)
    }

    public suspend fun updateProfile(displayName: String? = null, photoUrl: String? = null, locale: String? = null): PoolUser {
        val user = call("PATCH", listOf("me"), obj("display_name" to displayName, "photo_url" to photoUrl, "locale" to locale), true) as JsonObject
        replaceUser(user)
        return json.decodeFromJsonElement(user)
    }

    /** Every session of the user ends, this one too (cleared locally). */
    public suspend fun changePassword(currentPassword: String?, newPassword: String): JsonObject {
        val out = call("POST", listOf("me", "password"), obj("current_password" to currentPassword, "new_password" to newPassword), true) as JsonObject
        clearSession()
        return out
    }

    public suspend fun changeEmail(newEmail: String): JsonObject =
        call("POST", listOf("me", "email"), obj("new_email" to newEmail), true) as JsonObject

    public suspend fun confirmEmailChange(code: String? = null, token: String? = null): PoolUser? =
        userAnswer(call("POST", listOf("me", "email", "confirm"), obj("code" to code, "token" to token), true) as JsonObject)

    /** A guest becomes a real account (same id); the access token keeps `anon` until the next [refresh]. */
    public suspend fun upgradeAnonymous(email: String, password: String): PoolUser? =
        userAnswer(call("POST", listOf("me", "upgrade"), obj("email" to email, "password" to password), true) as JsonObject)

    /** Deletes the account (the [password] when the user has one); clears the session. */
    public suspend fun deleteAccount(password: String? = null): JsonObject {
        val out = call("DELETE", listOf("me"), obj("password" to password), true) as JsonObject
        clearSession()
        return out
    }

    /** Best-effort server call (revokes this session or, [everywhere], all), always clears locally. */
    public suspend fun signOut(everywhere: Boolean = false) {
        val cur = session
        try {
            if (cur != null) {
                var bearer = if (fresh(cur)) cur.accessToken else null
                if (bearer == null && everywhere && cur.refreshToken != null) bearer = getAccessToken()
                call("POST", listOf("signout"), obj("refresh_token" to cur.refreshToken, "everywhere" to everywhere), false, bearer)
            }
        } catch (e: AuthException) {
            // signed out locally anyway
        }
        clearSession()
    }

    // --- organizations (B2B) -----------------------------------------------------------------------------------------

    public suspend fun organizations(): OrganizationList = json.decodeFromJsonElement(call("GET", listOf("orgs"), null, true))

    public suspend fun createOrganization(name: String): Organization =
        json.decodeFromJsonElement(call("POST", listOf("orgs"), obj("name" to name), true))

    /** New tokens for another organization (serialized with the refreshes: it rotates the refresh token). */
    public suspend fun switchOrganization(orgId: String): ActiveOrg? {
        val bearer = getAccessToken()
        return refreshMutex.withLock {
            withContext(NonCancellable) {
                val cur = session ?: throw notSignedIn()
                val data = call("POST", listOf("orgs", "switch"), obj("org_id" to orgId, "refresh_token" to cur.refreshToken), true, bearer)
                saveTokens(data as JsonObject, cur.user)
                currentOrg
            }
        }
    }

    public suspend fun members(orgId: String, q: String = "", skip: Int = 0, limit: Int = 50): MemberPage =
        json.decodeFromJsonElement(call("GET", listOf("orgs", orgId, "members"), null, true,
            query = mapOf("q" to q, "skip" to skip.toString(), "limit" to limit.toString())))

    /** The answer may include a temporary password to hand over. */
    public suspend fun addMember(orgId: String, email: String, displayName: String? = null, password: String? = null, roles: List<String> = emptyList()): JsonObject =
        call("POST", listOf("orgs", orgId, "members"), obj("email" to email, "display_name" to (displayName ?: ""), "password" to password,
            "roles" to JsonArray(roles.map(::JsonPrimitive))), true) as JsonObject

    public suspend fun setMemberRoles(orgId: String, userId: String, roles: List<String>): JsonElement =
        call("PATCH", listOf("orgs", orgId, "members", userId), obj("roles" to JsonArray(roles.map(::JsonPrimitive))), true)

    public suspend fun removeMember(orgId: String, userId: String): JsonElement =
        call("DELETE", listOf("orgs", orgId, "members", userId), null, true)

    // --- hosted sign-in (OIDC code + PKCE) ---------------------------------------------------------------------------

    /**
     * Builds the hosted sign-in request (fresh state, nonce, PKCE S256) and keeps it in the storage for
     * [handleRedirectCallback]. Launch it with [OpenBackSignInContract].
     */
    public suspend fun buildAuthorizationRequest(options: AuthorizationOptions = AuthorizationOptions()): AuthorizationRequest {
        val redirect = options.redirectUri ?: redirectUri
            ?: throw IllegalStateException("A redirectUri is required (client option or AuthorizationOptions)")
        val request = AuthorizationRequest.create(issuer, clientId, redirect, options)
        withContext(io) { storage.set(pendingKey, request.toJson()) }
        return request
    }

    /**
     * Completes a hosted sign-in from the redirect URI the app received: checks `error`, `state` (constant time) and
     * `iss`, exchanges the code (PKCE), checks the ID token's nonce, keeps the session, returns the user.
     */
    public suspend fun handleRedirectCallback(callbackUri: String): PoolUser? {
        val params = AuthCrypto.queryParams(callbackUri)
        val tx = withContext(io) { AuthorizationRequest.fromJson(storage.get(pendingKey)) }
        if (params["error"] != null && tx != null && AuthCrypto.constantTimeEquals(tx.state, params["state"])) {
            withContext(io) { storage.remove(pendingKey) }
        }
        val code = checkCallback(params, tx, issuer)
        withContext(io) { storage.remove(pendingKey) }
        val form = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("redirect_uri", tx!!.redirectUri)
            .add("client_id", clientId)
            .add("code_verifier", tx.codeVerifier)
            .build()
        val data = withContext(NonCancellable) { postForm("$issuer/token", form) }
        val idToken = data.str("id_token")
        if (idToken != null) {
            val claims = AuthCrypto.decodeJwtPayload(idToken, json)
            if (claims == null || !AuthCrypto.constantTimeEquals(tx.nonce, claims.str("nonce"))) {
                throw AuthException(400, "invalid_nonce", "Nonce mismatch")
            }
            val aud = claims["aud"]
            val audOk = (aud is JsonPrimitive && aud.contentOrNull == clientId) ||
                (aud is JsonArray && aud.any { (it as? JsonPrimitive)?.contentOrNull == clientId })
            if (claims.str("iss") != issuer || !audOk) throw AuthException(400, "invalid_id_token", "ID token of another issuer or app")
        }
        saveTokens(data, null)
        return try {
            me()
        } catch (e: AuthException) {
            currentUser
        }
    }

    /** The end-session URL (with the ID token as hint when there is one). */
    public fun buildLogoutUrl(postLogoutRedirectUri: String? = null, state: String? = null): String =
        "$issuer/logout?" + AuthCrypto.query(linkedMapOf("client_id" to clientId, "id_token_hint" to session?.idToken,
            "post_logout_redirect_uri" to postLogoutRedirectUri, "state" to state))

    /**
     * Signs out ([signOut]) and returns the end-session URL to open with [OpenBackSignOutContract] (ends the hosted
     * page's browser session too).
     */
    public suspend fun signOutRedirect(postLogoutRedirectUri: String? = null, state: String? = null, everywhere: Boolean = false): String {
        val url = buildLogoutUrl(postLogoutRedirectUri, state)
        signOut(everywhere)
        return url
    }

    // --- internals ---------------------------------------------------------------------------------------------------

    private fun notSignedIn() = AuthException(401, "not_signed_in", "Not signed in")

    private fun fresh(s: Session) = s.accessToken != null && s.expiresAt - clock() > SKEW_MS

    private fun obj(vararg pairs: Pair<String, Any?>): JsonObject = buildJsonObject {
        for ((k, v) in pairs) {
            when (v) {
                null -> Unit
                is String -> put(k, v)
                is Boolean -> put(k, v)
                is Number -> put(k, v)
                is JsonElement -> put(k, v)
                else -> put(k, v.toString())
            }
        }
    }

    private fun recoveryCodes(data: JsonObject): List<String> =
        (data["recovery_codes"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } ?: emptyList()

    private fun url(segments: List<String>, query: Map<String, String>): HttpUrl {
        val b = "$issuer$API".toHttpUrl().newBuilder()
        segments.forEach { b.addPathSegment(it) }
        query.forEach { (k, v) -> b.addQueryParameter(k, v) }
        return b.build()
    }

    /**
     * A JSON API call. [signedIn]: needs the user's token ([bearer] or the current one); a 401 `token_*` then ends the
     * local session. `invalid_refresh_token` always does.
     */
    internal suspend fun call(
        method: String,
        segments: List<String>,
        body: JsonObject?,
        signedIn: Boolean,
        bearer: String? = null,
        query: Map<String, String> = emptyMap(),
    ): JsonElement {
        val token = bearer ?: if (signedIn) getAccessToken() else null
        val rb: RequestBody? = body?.toString()?.toRequestBody(JSON_TYPE)
        val req = Request.Builder().url(url(segments, query))
            .header("X-Client-Id", clientId)
            .header("Accept", "application/json")
            .method(method, rb ?: if (method == "POST" || method == "PATCH") ByteArray(0).toRequestBody(null) else null)
            .apply { if (token != null) header("Authorization", "Bearer $token") }
            .build()
        val (status, text) = execute(req)
        val data = parse(text)
        if (status !in 200..299) {
            val e = apiError(status, data)
            if (e.status == 401 && ((signedIn && e.code.startsWith("token_")) || e.code == "invalid_refresh_token")) clearSession()
            throw e
        }
        return data
    }

    private suspend fun postForm(url: String, form: FormBody): JsonObject {
        val req = Request.Builder().url(url).post(form).header("Accept", "application/json")
            .apply { if (clientSecret != null) header("Authorization", AuthCrypto.basicAuth(clientId, clientSecret)) }
            .build()
        val (status, text) = execute(req)
        val data = parse(text)
        if (status !in 200..299) {
            val obj = data as? JsonObject
            val error = obj?.str("error")
            if (error != null) throw AuthException(status, error, obj.str("error_description") ?: error, obj)
            throw apiError(status, data)
        }
        return data as? JsonObject ?: throw AuthException(status, "invalid_response", "Unexpected answer")
    }

    private suspend fun execute(req: Request): Pair<Int, String> = withContext(io) {
        try {
            http.newCall(req).execute().use { res -> res.code to (res.body?.string() ?: "") }
        } catch (e: IOException) {
            throw AuthException(0, "network_error", "Network error: ${e.javaClass.simpleName}", null, e)
        }
    }

    private fun parse(text: String): JsonElement = try {
        if (text.isBlank()) JsonNull else json.parseToJsonElement(text)
    } catch (e: Exception) {
        JsonNull
    }

    private fun apiError(status: Int, data: JsonElement): AuthException {
        val detail = (data as? JsonObject)?.get("detail")
        var code: String? = null
        var message: String? = null
        when (detail) {
            is JsonObject -> {
                code = detail.str("code")
                message = detail.str("message")
            }
            is JsonPrimitive -> message = detail.contentOrNull
            is JsonArray -> message = "Invalid request"
            else -> Unit
        }
        val obj = data as? JsonObject
        val oauthError = obj?.str("error")
        if (code == null && oauthError != null) {
            code = oauthError
            message = message ?: obj.str("error_description")
        }
        return AuthException(status, code ?: "http_$status", message, detail)
    }

    private suspend fun outcome(data: JsonElement): AuthOutcome {
        val obj = data as? JsonObject ?: JsonObject(emptyMap())
        val details = JsonObject(obj.filterKeys { it !in SECRET_FIELDS })
        val status = obj.str("status") ?: ""
        return when (status) {
            "ok" -> {
                if (obj.str("access_token") != null) saveTokens(obj, null)
                AuthOutcome.SignedIn(
                    user = (obj["user"] as? JsonObject)?.let { runCatching { json.decodeFromJsonElement<PoolUser>(it) }.getOrNull() },
                    org = (obj["org"] as? JsonObject)?.let { runCatching { json.decodeFromJsonElement<ActiveOrg>(it) }.getOrNull() },
                    recoveryCodes = recoveryCodes(obj),
                    details = details,
                )
            }
            "verification_required" -> AuthOutcome.VerificationRequired(details)
            "mfa_required" -> AuthOutcome.MfaRequired(obj.str("mfa_token") ?: "", details)
            "mfa_enroll_required" -> AuthOutcome.MfaEnrollRequired(obj.str("mfa_token") ?: "", details)
            "password_change_required" -> AuthOutcome.PasswordChangeRequired(obj.str("change_token") ?: "", details)
            else -> AuthOutcome.Unknown(status, details)
        }
    }

    private suspend fun saveTokens(data: JsonObject, userFallback: JsonObject?) {
        val cur = session
        val user = data["user"] as? JsonObject ?: userFallback
        val expiresIn = data["expires_in"]?.jsonPrimitive?.longOrNull?.takeIf { it > 0 } ?: 900L
        save(
            Session(
                accessToken = data.str("access_token"),
                refreshToken = data.str("refresh_token"),
                idToken = data.str("id_token") ?: cur?.idToken,
                expiresAt = clock() + expiresIn * 1000L,
                user = user,
                org = data["org"] as? JsonObject,
            ),
        )
    }

    private suspend fun userAnswer(data: JsonObject): PoolUser? {
        val user = data["user"] as? JsonObject ?: return null
        val cur = session
        if (cur?.user != null && cur.user.str("id") == user.str("id")) replaceUser(user)
        return json.decodeFromJsonElement<PoolUser>(user)
    }

    private suspend fun replaceUser(user: JsonObject) {
        val cur = session ?: return
        save(cur.copy(user = user))
    }

    private suspend fun clearSession() {
        if (session == null) {
            withContext(io) { storage.remove(storageKey) }
            return
        }
        save(null)
    }

    private fun load(): Session? = try {
        Session.fromJson(storage.get(storageKey))
    } catch (e: Exception) {
        null
    }

    private suspend fun save(next: Session?) {
        withContext(io) {
            if (next?.refreshToken != null) storage.set(storageKey, next.toJson()) else storage.remove(storageKey)
        }
        session = next
        _authState.value = stateOf(next)
        val user = currentUser
        val org = currentOrg
        for (l in listeners) runCatching { l(user, org) }
    }

    private fun stateOf(s: Session?): AuthState =
        if (s == null) AuthState.SignedOut else AuthState.SignedIn(s.typedUser(), s.typedOrg())

    /** The stored session: `{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}`. */
    internal data class Session(
        val accessToken: String?,
        val refreshToken: String?,
        val idToken: String?,
        val expiresAt: Long,
        val user: JsonObject?,
        val org: JsonObject?,
    ) {
        fun typedUser(): PoolUser? = user?.let { runCatching { json.decodeFromJsonElement<PoolUser>(it) }.getOrNull() }
        fun typedOrg(): ActiveOrg? = org?.let { runCatching { json.decodeFromJsonElement<ActiveOrg>(it) }.getOrNull() }

        fun toJson(): String = buildJsonObject {
            put("accessToken", accessToken)
            put("refreshToken", refreshToken)
            put("idToken", idToken)
            put("expiresAt", expiresAt)
            put("user", user ?: JsonNull)
            put("org", org ?: JsonNull)
        }.toString()

        override fun toString(): String = "Session(expiresAt=$expiresAt, tokens=***)"

        companion object {
            fun fromJson(text: String?): Session? {
                if (text.isNullOrBlank()) return null
                val o = json.parseToJsonElement(text) as? JsonObject ?: return null
                val rt = o.str("refreshToken") ?: return null
                return Session(o.str("accessToken"), rt, o.str("idToken"), o["expiresAt"]?.jsonPrimitive?.longOrNull ?: 0L,
                    o["user"] as? JsonObject, o["org"] as? JsonObject)
            }
        }
    }
}

private val SECRET_FIELDS = setOf("access_token", "refresh_token", "id_token")

internal fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull

/** Checks a hosted sign-in callback: error, state (constant time), iss (RFC 9207). Returns the code. */
internal fun checkCallback(params: Map<String, String>, tx: AuthorizationRequest?, issuer: String): String {
    val error = params["error"]
    if (!error.isNullOrEmpty()) {
        throw AuthException(400, error, params["error_description"]?.takeIf { it.isNotEmpty() } ?: error)
    }
    if (tx == null) throw AuthException(400, "no_pending_request", "No sign-in in progress")
    if (!AuthCrypto.constantTimeEquals(tx.state, params["state"])) throw AuthException(400, "invalid_state", "Sign-in state mismatch")
    val iss = params["iss"]
    if (iss != null && iss != issuer) throw AuthException(400, "invalid_issuer", "Unexpected issuer")
    return params["code"]?.takeIf { it.isNotEmpty() } ?: throw AuthException(400, "invalid_request", "No authorization code in the callback")
}
