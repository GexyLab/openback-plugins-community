package io.openback.appauth.android

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.SocketPolicy
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class OpenBackAuthTest {
    private lateinit var pool: FakePool
    private lateinit var storage: InMemoryTokenStorage
    private lateinit var auth: OpenBackAuth
    private val key = "openback.auth.uapp_android"

    @Before
    fun setUp() {
        pool = FakePool()
        storage = InMemoryTokenStorage()
        auth = OpenBackAuth(pool.issuer + "/", "uapp_android",
            OpenBackAuth.Options(redirectUri = "com.example.app:/oauth2redirect", storage = storage))
    }

    @After
    fun tearDown() {
        assertTrue("fake pool handler failed: ${pool.failures}", pool.failures.isEmpty())
        pool.close()
    }

    private fun okOutcome(rt: String, expiresIn: Long) =
        """{"status":"ok","access_token":"${TestTokens.accessToken()}","token_type":"Bearer","refresh_token":"$rt",""" +
            """"expires_in":$expiresIn,"user":${TestTokens.userJson()},"org":null}"""

    private fun tokens(rt: String, expiresIn: Long, extra: String = "") =
        """{"access_token":"${TestTokens.accessToken()}","token_type":"Bearer","expires_in":$expiresIn,"scope":"openid",""" +
            """"refresh_token":"$rt","refresh_expires_in":1000$extra}"""

    private fun signIn(rt: String = "obur_1", expiresIn: Long = 900) = runBlocking {
        val body = okOutcome(rt, expiresIn)
        pool.route("POST", "/api/v1/signin/password") { FakePool.json(200, body) }
        assertTrue(auth.signInWithPassword("ada@example.com", "pw") is AuthOutcome.SignedIn)
    }

    private fun stored(): JsonObject = Json.parseToJsonElement(storage.get(key)!!).jsonObject

    private suspend fun <T> expectError(block: suspend () -> T): AuthException {
        try {
            block()
        } catch (e: AuthException) {
            return e
        }
        fail("expected AuthException")
        throw IllegalStateException()
    }

    @Test
    fun passwordSignInKeepsTheSessionAndUpdatesTheState() = runBlocking {
        val seen = mutableListOf<String>()
        val unsubscribe = auth.onAuthStateChanged { u, _ -> seen.add(u?.id ?: "out") }
        assertEquals(listOf("out"), seen)
        assertEquals(AuthState.SignedOut, auth.authState.value)

        signIn()
        assertEquals(listOf("out", "usr_1"), seen)
        val state = auth.authState.value as AuthState.SignedIn
        assertEquals("Ada", state.user!!.displayName)
        assertTrue(state.user!!.isTotpEnabled)
        assertTrue(auth.isSignedIn)
        assertEquals("usr_1", auth.accessTokenClaims!!["sub"]!!.jsonPrimitive.content)

        val req = pool.last()
        assertEquals("uapp_android", req.getHeader("X-Client-Id"))
        assertEquals("application/json", req.getHeader("Accept"))
        assertTrue(req.getHeader("Content-Type")!!.startsWith("application/json"))
        assertNull(req.getHeader("Origin"))
        val body = Json.parseToJsonElement(req.body.readUtf8()).jsonObject
        assertEquals("ada@example.com", body["email"]!!.jsonPrimitive.content)
        assertFalse(body.containsKey("org_id"))

        val s = stored()
        assertEquals("obur_1", s["refreshToken"]!!.jsonPrimitive.content)
        assertTrue(s["expiresAt"]!!.jsonPrimitive.long > System.currentTimeMillis())
        assertEquals("usr_1", s["user"]!!.jsonObject["id"]!!.jsonPrimitive.content)
        assertTrue(s.containsKey("accessToken") && s.containsKey("idToken") && s.containsKey("org"))

        // a new client on the same storage restores the session
        val again = OpenBackAuth(pool.issuer, "uapp_android", OpenBackAuth.Options(storage = storage))
        assertEquals("usr_1", again.currentUser!!.id)
        assertTrue(again.authState.value is AuthState.SignedIn)

        unsubscribe()
        auth.signOut()
        assertEquals(2, seen.size)
        assertEquals(AuthState.SignedOut, auth.authState.value)
    }

    @Test
    fun otherOutcomesAreTypedAndDoNotSignIn() = runBlocking {
        pool.route("POST", "/api/v1/signin/password") { FakePool.json(200, """{"status":"mfa_required","mfa_token":"mfa_1"}""") }
        val res = auth.signInWithPassword("a@b.c", "pw")
        assertEquals("mfa_1", (res as AuthOutcome.MfaRequired).mfaToken)
        assertFalse(auth.isSignedIn)

        val ok = okOutcome("obur_2", 900)
        pool.route("POST", "/api/v1/signin/mfa") { FakePool.json(200, ok) }
        val done = auth.verifyMfa("mfa_1", "123456") as AuthOutcome.SignedIn
        assertEquals("usr_1", done.user!!.id)
        assertFalse(done.details.containsKey("access_token") || done.details.containsKey("refresh_token"))
        assertTrue(auth.isSignedIn)

        pool.route("POST", "/api/v1/signup") { FakePool.json(200, """{"status":"password_change_required","change_token":"chg"}""") }
        assertEquals("chg", (auth.signUp("b@c.d", "pw") as AuthOutcome.PasswordChangeRequired).changeToken)
        pool.route("POST", "/api/v1/signin/email-code/verify") { FakePool.json(200, """{"status":"verification_required"}""") }
        assertTrue(auth.signInWithEmailCode("a@b.c", "1") is AuthOutcome.VerificationRequired)
        pool.route("POST", "/api/v1/signin/anonymous") { FakePool.json(200, """{"status":"mfa_enroll_required","mfa_token":"m2"}""") }
        assertEquals("m2", (auth.signInAnonymously() as AuthOutcome.MfaEnrollRequired).mfaToken)
        pool.route("POST", "/api/v1/signin/anonymous") { FakePool.json(200, """{"status":"brand_new"}""") }
        assertEquals("brand_new", (auth.signInAnonymously() as AuthOutcome.Unknown).status)
    }

    @Test
    fun mapsErrors() = runBlocking {
        pool.route("POST", "/api/v1/signin/password") {
            FakePool.json(401, """{"detail":{"code":"invalid_credentials","message":"Wrong email or password"}}""")
        }
        val e = expectError { auth.signInWithPassword("a@b.c", "x") }
        assertEquals(401, e.status)
        assertEquals("invalid_credentials", e.code)
        assertEquals("Wrong email or password", e.message)

        pool.route("POST", "/api/v1/signup") {
            FakePool.json(422, """{"detail":{"code":"weak_password","message":"Weak","problems":["min_length"]}}""")
        }
        val weak = expectError { auth.signUp("a@b.c", "x") }
        assertEquals("weak_password", weak.code)
        assertEquals("min_length", (weak.detail as JsonObject)["problems"].toString().trim('[', ']', '"'))

        pool.route("POST", "/api/v1/password/forgot") { FakePool.json(422, """{"detail":[{"loc":["body","email"]}]}""") }
        assertEquals("http_422", expectError { auth.sendPasswordReset("x") }.code)
        pool.route("POST", "/api/v1/signin/email-code") { FakePool.json(429, """{"detail":"Too many"}""") }
        val many = expectError { auth.sendEmailCode("x") }
        assertEquals("http_429", many.code)
        assertEquals("Too many", many.message)
        assertEquals("not_signed_in", expectError { auth.getAccessToken() }.code)
    }

    @Test
    fun freshTokenIsReusedExpiringOneIsRefreshed() = runBlocking {
        signIn("obur_1", 900)
        val first = auth.getAccessToken()
        assertEquals(first, auth.getAccessToken())
        assertEquals(0, pool.hits("POST", "/api/v1/token/refresh"))

        signIn("obur_2", 30)
        val body = tokens("obur_3", 900)
        pool.route("POST", "/api/v1/token/refresh") { r ->
            assertEquals("obur_2", Json.parseToJsonElement(r.body.readUtf8()).jsonObject["refresh_token"]!!.jsonPrimitive.content)
            FakePool.json(200, body)
        }
        auth.getAccessToken()
        assertEquals(1, pool.hits("POST", "/api/v1/token/refresh"))
        assertEquals("obur_3", stored()["refreshToken"]!!.jsonPrimitive.content)
        assertEquals("usr_1", auth.currentUser!!.id)
    }

    @Test
    fun refreshIsSingleFlight() = runBlocking {
        signIn("obur_1", 10)
        val calls = AtomicInteger()
        val body = tokens("obur_2", 900)
        pool.route("POST", "/api/v1/token/refresh") { r ->
            calls.incrementAndGet()
            val rt = Json.parseToJsonElement(r.body.readUtf8()).jsonObject["refresh_token"]!!.jsonPrimitive.content
            if (rt != "obur_1") FakePool.json(401, """{"detail":{"code":"invalid_refresh_token","message":"reuse"}}""")
            else FakePool.json(200, body).setBodyDelay(300, TimeUnit.MILLISECONDS)
        }
        val tokens = (1..12).map { async(Dispatchers.Default) { auth.getAccessToken() } }.awaitAll()
        assertEquals(1, tokens.toSet().size)
        assertEquals(1, calls.get())
        assertTrue(auth.isSignedIn)
    }

    @Test
    fun invalidRefreshTokenEndsTheSession() = runBlocking {
        signIn("obur_1", 10)
        val seen = mutableListOf<String>()
        auth.onAuthStateChanged { u, _ -> seen.add(u?.id ?: "out") }
        pool.route("POST", "/api/v1/token/refresh") {
            FakePool.json(401, """{"detail":{"code":"invalid_refresh_token","message":"Session expired"}}""")
        }
        val e = expectError { auth.getAccessToken() }
        assertEquals("invalid_refresh_token", e.code)
        assertTrue(e.isSessionEnded)
        assertFalse(auth.isSignedIn)
        assertNull(storage.get(key))
        assertEquals(listOf("usr_1", "out"), seen)
        assertEquals(AuthState.SignedOut, auth.authState.value)
    }

    @Test
    fun networkErrorDuringRefreshIsNotRetried() = runBlocking {
        signIn("obur_1", 10)
        pool.route("POST", "/api/v1/token/refresh") { MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) }
        val e = expectError { auth.getAccessToken() }
        assertEquals("network_error", e.code)
        assertEquals(1, pool.hits("POST", "/api/v1/token/refresh"))
        assertTrue(auth.isSignedIn)
        assertEquals("obur_1", stored()["refreshToken"]!!.jsonPrimitive.content)
    }

    @Test
    fun tokenErrorOnSignedInCallClearsTheSession() = runBlocking {
        signIn()
        pool.route("GET", "/api/v1/me") { FakePool.json(401, """{"detail":{"code":"token_revoked","message":"x"}}""") }
        assertEquals("token_revoked", expectError { auth.me() }.code)
        assertFalse(auth.isSignedIn)
    }

    @Test
    fun signedInCallsAndOrganizations() = runBlocking {
        signIn()
        val token = auth.getAccessToken()
        pool.route("GET", "/api/v1/me") { FakePool.json(200, TestTokens.userJson(name = "Ada L.")) }
        assertEquals("Ada L.", auth.me().displayName)
        assertEquals("Bearer $token", pool.last().getHeader("Authorization"))
        assertEquals("Ada L.", auth.currentUser!!.displayName)

        pool.route("GET", "/api/v1/orgs/org%201/members") { r ->
            assertEquals("ada", r.requestUrl!!.queryParameter("q"))
            assertEquals("10", r.requestUrl!!.queryParameter("skip"))
            FakePool.json(200, """{"items":[{"user_id":"usr_2","email":"b@x","display_name":"B","disabled":false,"roles":["member"],"created_at":"t"}],"total":1,"roles":[{"key":"member","label":"Member"}]}""")
        }
        val page = auth.members("org 1", "ada", 10, 5)
        assertEquals("usr_2", page.items[0].userId)
        assertEquals("Member", page.roles[0].label)

        pool.route("POST", "/api/v1/orgs/switch") { r ->
            val b = Json.parseToJsonElement(r.body.readUtf8()).jsonObject
            assertEquals("obur_1", b["refresh_token"]!!.jsonPrimitive.content)
            assertEquals("org_2", b["org_id"]!!.jsonPrimitive.content)
            FakePool.json(200, tokens("obur_2", 900, ""","org":{"id":"org_2","name":"Beta","roles":["admin"],"choices":2}"""))
        }
        val org = auth.switchOrganization("org_2")!!
        assertEquals("Beta", org.name)
        assertEquals(2, org.choices)
        assertEquals("obur_2", stored()["refreshToken"]!!.jsonPrimitive.content)

        pool.route("POST", "/api/v1/mfa/enroll") { FakePool.json(200, """{"secret":"ABC","otpauth_uri":"otpauth://totp/x"}""") }
        val en = auth.enrollMfa()
        assertEquals("otpauth://totp/x", en.otpauthUri)
        assertFalse(en.toString().contains("ABC"))
        pool.route("POST", "/api/v1/mfa/enroll/confirm") { FakePool.json(200, """{"status":"enabled","recovery_codes":["r1","r2"]}""") }
        assertEquals(listOf("r1", "r2"), auth.confirmMfa("123456").recoveryCodes)
    }

    @Test
    fun signOutIsBestEffortAndChangePasswordClears() = runBlocking {
        signIn()
        pool.route("POST", "/api/v1/signout") { FakePool.json(500, "{}") }
        auth.signOut(everywhere = true)
        assertFalse(auth.isSignedIn)
        val b = Json.parseToJsonElement(pool.last().body.readUtf8()).jsonObject
        assertEquals("obur_1", b["refresh_token"]!!.jsonPrimitive.content)
        assertTrue(b["everywhere"]!!.jsonPrimitive.boolean)

        signIn("obur_5")
        pool.route("POST", "/api/v1/me/password") { FakePool.json(200, """{"status":"password_changed"}""") }
        auth.changePassword("old", "new-password-123")
        assertFalse(auth.isSignedIn)
    }

    @Test
    fun hostedSignInCompletesFromTheStoredRequest() = runBlocking {
        val req = auth.buildAuthorizationRequest()
        assertNotNull(storage.get("$key.pkce"))
        val idToken = TestTokens.jwt(mapOf("iss" to pool.issuer, "aud" to "uapp_android", "sub" to "usr_1", "nonce" to req.nonce))
        pool.route("POST", "/token") { r ->
            val f = r.body.readUtf8()
            val q = AuthCrypto.queryParams("x:/?$f")
            assertEquals("authorization_code", q["grant_type"])
            assertEquals("the-code", q["code"])
            assertEquals(req.codeVerifier, q["code_verifier"])
            assertEquals("com.example.app:/oauth2redirect", q["redirect_uri"])
            assertEquals("uapp_android", q["client_id"])
            assertNull(r.getHeader("Authorization"))
            FakePool.json(200, """{"access_token":"${TestTokens.accessToken()}","token_type":"Bearer","expires_in":900,"refresh_token":"obur_x","id_token":"$idToken"}""")
        }
        pool.route("GET", "/api/v1/me") { FakePool.json(200, TestTokens.userJson()) }
        // the process restarted while the Custom Tab was open: a new client finishes from the storage
        val restarted = OpenBackAuth(pool.issuer, "uapp_android", OpenBackAuth.Options(storage = storage))
        val user = restarted.handleRedirectCallback(
            "com.example.app:/oauth2redirect?code=the-code&state=${req.state}&iss=${AuthCrypto.encode(pool.issuer)}")
        assertEquals("usr_1", user!!.id)
        assertTrue(restarted.isSignedIn)
        assertNull(storage.get("$key.pkce"))
        assertTrue(restarted.buildLogoutUrl("com.example.app:/bye", "s").contains("id_token_hint=$idToken"))
        val logout = restarted.signOutRedirect("com.example.app:/bye")
        assertTrue(logout.startsWith(pool.issuer + "/logout?client_id=uapp_android"))
        assertFalse(restarted.isSignedIn)
    }

    @Test
    fun hostedSignInChecks() = runBlocking {
        val req = auth.buildAuthorizationRequest()
        assertEquals("invalid_state", expectError { auth.handleRedirectCallback("com.example.app:/oauth2redirect?code=c&state=nope") }.code)
        assertEquals("invalid_issuer", expectError {
            auth.handleRedirectCallback("com.example.app:/oauth2redirect?code=c&state=${req.state}&iss=https%3A%2F%2Fevil")
        }.code)
        val denied = expectError { auth.handleRedirectCallback("com.example.app:/oauth2redirect?error=access_denied&error_description=No&state=${req.state}") }
        assertEquals("access_denied", denied.code)
        assertEquals("No", denied.message)
        assertEquals("no_pending_request", expectError { auth.handleRedirectCallback("com.example.app:/oauth2redirect?code=c&state=${req.state}") }.code)
        assertEquals(0, pool.hits("POST", "/token"))

        val again = auth.buildAuthorizationRequest()
        val badNonce = TestTokens.jwt(mapOf("iss" to pool.issuer, "aud" to "uapp_android", "nonce" to "other"))
        pool.route("POST", "/token") { FakePool.json(200, """{"access_token":"a","expires_in":900,"refresh_token":"r","id_token":"$badNonce"}""") }
        assertEquals("invalid_nonce", expectError { auth.handleRedirectCallback("com.example.app:/oauth2redirect?code=c&state=${again.state}") }.code)
        assertFalse(auth.isSignedIn)

        val third = auth.buildAuthorizationRequest()
        pool.route("POST", "/token") { FakePool.json(400, """{"error":"invalid_grant","error_description":"PKCE verification failed"}""") }
        val grant = expectError { auth.handleRedirectCallback("com.example.app:/oauth2redirect?code=c&state=${third.state}") }
        assertEquals("invalid_grant", grant.code)
        assertEquals(400, grant.status)
    }

    @Test
    fun okHttpInterceptorAndAuthenticator() = runBlocking {
        signIn("obur_1", 900)
        val first = auth.getAccessToken()
        val apiCalls = AtomicInteger()
        pool.route("GET", "/orders") { r ->
            if (apiCalls.incrementAndGet() == 1) {
                assertEquals("Bearer $first", r.getHeader("Authorization"))
                FakePool.json(401, """{"error":"invalid_token"}""")
            } else {
                FakePool.json(200, """{"orders":[]}""")
            }
        }
        val renewed = tokens("obur_2", 900)
        pool.route("POST", "/api/v1/token/refresh") { FakePool.json(200, renewed) }
        val api = OkHttpClient.Builder()
            .addInterceptor(OpenBackAuthInterceptor(auth) { it.url.encodedPath.startsWith("/gateway/") })
            .authenticator(OpenBackAuthAuthenticator(auth))
            .build()
        val res = kotlinx.coroutines.withContext(Dispatchers.IO) {
            api.newCall(Request.Builder().url(pool.issuer + "/orders").build()).execute()
        }
        res.use { assertEquals(200, it.code) }
        assertEquals(2, apiCalls.get())
        assertEquals(1, pool.hits("POST", "/api/v1/token/refresh"))
        assertEquals("obur_2", stored()["refreshToken"]!!.jsonPrimitive.content)
    }
}
