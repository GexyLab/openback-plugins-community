package io.openback.appauth.android

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom

/** Pure helpers (no Android API, so they run in JVM unit tests): CSPRNG strings, PKCE, base64url, queries, JWT payload. */
internal object AuthCrypto {
    private val random = SecureRandom()

    fun b64url(bytes: ByteArray): String = bytes.toByteString().base64Url().trimEnd('=')

    /** [bytes] random bytes from the platform CSPRNG, base64url. */
    fun randomString(bytes: Int): String = ByteArray(bytes).also { random.nextBytes(it) }.let(::b64url)

    /** PKCE verifier: 48 random bytes = 64 base64url characters (RFC 7636: 43..128). */
    fun codeVerifier(): String = randomString(48)

    /** S256 challenge. */
    fun codeChallenge(verifier: String): String = b64url(verifier.encodeUtf8().sha256().toByteArray())

    /** Constant-time comparison; null never matches. */
    fun constantTimeEquals(a: String?, b: String?): Boolean {
        if (a == null || b == null) return false
        return MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
    }

    fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    fun query(params: Map<String, String?>): String =
        params.filterValues { it != null }.entries.joinToString("&") { (k, v) -> "${encode(k)}=${encode(v!!)}" }

    /** The query parameters of a URL (first value of each name); works for custom schemes too. */
    fun queryParams(url: String): Map<String, String> {
        val raw = try {
            URI(url.trim()).rawQuery
        } catch (e: Exception) {
            url.substringAfter('?', "").substringBefore('#').ifEmpty { null }
        } ?: return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in raw.split('&')) {
            if (pair.isEmpty()) continue
            val k = URLDecoder.decode(pair.substringBefore('='), "UTF-8")
            val v = if ('=' in pair) URLDecoder.decode(pair.substringAfter('='), "UTF-8") else ""
            if (k !in out) out[k] = v
        }
        return out
    }

    /** The payload of a JWT, NOT verified (display, nonce check of a token received over TLS); null if not a JWT. */
    fun decodeJwtPayload(token: String?, json: Json): JsonObject? {
        val part = token?.split('.')?.getOrNull(1) ?: return null
        val bytes = part.decodeBase64() ?: return null
        return try {
            json.parseToJsonElement(bytes.utf8()) as? JsonObject
        } catch (e: Exception) {
            null
        }
    }

    /** RFC 6749 2.3.1 Basic client authentication (id and secret form-url-encoded first). */
    fun basicAuth(clientId: String, secret: String): String =
        "Basic " + "${encode(clientId)}:${encode(secret)}".encodeUtf8().base64()
}
