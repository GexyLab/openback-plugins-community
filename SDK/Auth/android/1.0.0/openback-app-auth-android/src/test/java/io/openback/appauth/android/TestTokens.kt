package io.openback.appauth.android

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** Test helpers: unsigned JWT-shaped tokens (the client never verifies signatures) and a routed MockWebServer. */
object TestTokens {
    fun jwt(claims: Map<String, Any?>): String {
        val header = AuthCrypto.b64url("""{"alg":"ES256","typ":"at+jwt","kid":"k1"}""".toByteArray())
        val payload = AuthCrypto.b64url(JsonObject(claims.mapValues { (_, v) -> toJson(v) }).toString().toByteArray())
        return "$header.$payload.c2ln"
    }

    private fun toJson(v: Any?): kotlinx.serialization.json.JsonElement = when (v) {
        null -> kotlinx.serialization.json.JsonNull
        is String -> JsonPrimitive(v)
        is Number -> JsonPrimitive(v)
        is Boolean -> JsonPrimitive(v)
        is List<*> -> JsonArray(v.map(::toJson))
        else -> JsonPrimitive(v.toString())
    }

    fun accessToken(sub: String = "usr_1"): String =
        jwt(mapOf("sub" to sub, "aud" to "uapp_android", "exp" to System.currentTimeMillis() / 1000 + 900, "roles" to listOf("member")))

    fun userJson(id: String = "usr_1", name: String = "Ada"): String =
        """{"id":"$id","email":"ada@example.com","email_verified":true,"display_name":"$name","photo_url":null,"locale":"en",""" +
            """"attributes":{"plan":"pro"},"anonymous":false,"created_at":"2026-10-01T10:00:00Z","last_login_at":null,"mfa":{"totp":true}}"""
}

/** MockWebServer with routes "METHOD /path" → handler; counts hits. */
class FakePool : AutoCloseable {
    val server = MockWebServer()
    private val routes = ConcurrentHashMap<String, (RecordedRequest) -> MockResponse>()
    private val hits = ConcurrentHashMap<String, AtomicInteger>()
    val requests = CopyOnWriteArrayList<RecordedRequest>()
    val failures = CopyOnWriteArrayList<Throwable>()

    init {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                requests.add(request)
                val key = "${request.method} ${request.requestUrl!!.encodedPath}"
                hits.getOrPut(key) { AtomicInteger() }.incrementAndGet()
                val handler = routes[key] ?: return json(404, """{"detail":{"code":"not_found","message":"Not found"}}""")
                return try {
                    handler(request)
                } catch (t: Throwable) {
                    failures.add(t)
                    MockResponse().setResponseCode(500)
                }
            }
        }
        server.start()
    }

    val issuer: String get() = server.url("/gateway/shop/auth/main").toString()

    fun route(method: String, issuerPath: String, handler: (RecordedRequest) -> MockResponse) {
        routes["$method /gateway/shop/auth/main$issuerPath"] = handler
    }

    fun hits(method: String, issuerPath: String): Int = hits["$method /gateway/shop/auth/main$issuerPath"]?.get() ?: 0

    fun last(): RecordedRequest = requests.last()

    override fun close() = server.shutdown()

    companion object {
        fun json(code: Int, body: String): MockResponse =
            MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)
    }
}
