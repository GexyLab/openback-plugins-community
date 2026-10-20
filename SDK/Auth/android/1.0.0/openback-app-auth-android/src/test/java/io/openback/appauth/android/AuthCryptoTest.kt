package io.openback.appauth.android

import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthCryptoTest {
    @Test
    fun pkceChallengeMatchesRfc7636Vector() {
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            AuthCrypto.codeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        )
    }

    @Test
    fun verifierIsLongRandomAndUrlSafe() {
        val a = AuthCrypto.codeVerifier()
        val b = AuthCrypto.codeVerifier()
        assertNotEquals(a, b)
        assertTrue(a.length in 43..128)
        assertTrue(a.matches(Regex("[A-Za-z0-9_-]+")))
    }

    @Test
    fun constantTimeEquals() {
        assertTrue(AuthCrypto.constantTimeEquals("abc", "abc"))
        assertFalse(AuthCrypto.constantTimeEquals("abc", "abd"))
        assertFalse(AuthCrypto.constantTimeEquals("abc", null))
        assertFalse(AuthCrypto.constantTimeEquals(null, null))
    }

    @Test
    fun queryParamsOfACustomSchemeRedirect() {
        val q = AuthCrypto.queryParams("com.example.app:/oauth2redirect?code=a%2Bb&state=s1&iss=https%3A%2F%2Fx%2Fauth#frag")
        assertEquals("a+b", q["code"])
        assertEquals("s1", q["state"])
        assertEquals("https://x/auth", q["iss"])
        assertTrue(AuthCrypto.queryParams("com.example.app:/oauth2redirect").isEmpty())
    }

    @Test
    fun decodesAJwtPayloadWithoutVerifying() {
        val token = TestTokens.jwt(mapOf("sub" to "usr_1", "nonce" to "n"))
        assertEquals("usr_1", AuthCrypto.decodeJwtPayload(token, OpenBackAuth.json)!!["sub"]!!.jsonPrimitive.content)
        assertNull(AuthCrypto.decodeJwtPayload("not-a-jwt", OpenBackAuth.json))
        assertNull(AuthCrypto.decodeJwtPayload(null, OpenBackAuth.json))
    }

    @Test
    fun basicAuthEncodesIdAndSecret() {
        assertEquals("Basic dWFwcF94OnMlM0FlY3JldA==", AuthCrypto.basicAuth("uapp_x", "s:ecret"))
    }

    @Test
    fun authorizationRequestCarriesPkceStateNonceAndExtras() {
        val req = AuthorizationRequest.create(
            "https://api.example.com/gateway/shop/auth/main", "uapp_android", "com.example.app:/oauth2redirect",
            AuthorizationOptions(provider = "uprov_g", orgId = "org_1", prompt = "login", screenHint = "signup",
                loginHint = "a@b.c", maxAge = 60, uiLocales = "it"),
        )
        val q = AuthCrypto.queryParams(req.url)
        assertTrue(req.url.startsWith("https://api.example.com/gateway/shop/auth/main/authorize?"))
        assertEquals("code", q["response_type"])
        assertEquals("uapp_android", q["client_id"])
        assertEquals("com.example.app:/oauth2redirect", q["redirect_uri"])
        assertEquals("openid profile email", q["scope"])
        assertEquals("S256", q["code_challenge_method"])
        assertEquals(AuthCrypto.codeChallenge(req.codeVerifier), q["code_challenge"])
        assertEquals(req.state, q["state"])
        assertEquals(req.nonce, q["nonce"])
        assertEquals("uprov_g", q["provider"])
        assertEquals("org_1", q["org_id"])
        assertEquals("login", q["prompt"])
        assertEquals("signup", q["screen_hint"])
        assertEquals("a@b.c", q["login_hint"])
        assertEquals("60", q["max_age"])
        assertEquals("it", q["ui_locales"])
        assertEquals(req, AuthorizationRequest.fromJson(req.toJson()))
        assertFalse(req.toString().contains(req.codeVerifier))
        assertNull(AuthorizationRequest.fromJson("{oops"))
    }

    @Test
    fun callbackChecks() {
        val tx = AuthorizationRequest("u", "state-1", "nonce-1", "verifier", "com.example.app:/cb")
        val issuer = "https://x/auth"
        assertEquals("c", checkCallback(mapOf("code" to "c", "state" to "state-1", "iss" to issuer), tx, issuer))
        assertEquals("c", checkCallback(mapOf("code" to "c", "state" to "state-1"), tx, issuer))
        fun code(params: Map<String, String>, t: AuthorizationRequest? = tx) =
            assertThrows(AuthException::class.java) { checkCallback(params, t, issuer) }.code
        assertEquals("invalid_state", code(mapOf("code" to "c", "state" to "other")))
        assertEquals("invalid_state", code(mapOf("code" to "c")))
        assertEquals("invalid_issuer", code(mapOf("code" to "c", "state" to "state-1", "iss" to "https://evil")))
        assertEquals("login_required", code(mapOf("error" to "login_required", "state" to "state-1")))
        assertEquals("no_pending_request", code(mapOf("code" to "c", "state" to "state-1"), null))
        assertEquals("invalid_request", code(mapOf("state" to "state-1")))
    }
}
