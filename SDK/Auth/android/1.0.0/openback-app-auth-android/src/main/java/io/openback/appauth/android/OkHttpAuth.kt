package io.openback.appauth.android

import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/**
 * Adds `Authorization: Bearer <access token>` to the requests of YOUR API's OkHttpClient (renewing the token when
 * needed). Limit it to your API's hosts with [shouldAuthorize] so the token never leaks to third parties. Never add it
 * to the OkHttpClient given to [OpenBackAuth] itself. When signed out the request goes without the header.
 *
 * ```
 * val api = OkHttpClient.Builder()
 *     .addInterceptor(OpenBackAuthInterceptor(auth) { it.url.host == "api.example.com" })
 *     .authenticator(OpenBackAuthAuthenticator(auth))
 *     .build()
 * ```
 */
public class OpenBackAuthInterceptor @JvmOverloads constructor(
    private val auth: OpenBackAuth,
    private val shouldAuthorize: (Request) -> Boolean = { true },
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (!shouldAuthorize(request) || request.header("Authorization") != null || !auth.isSignedIn) {
            return chain.proceed(request)
        }
        val token = try {
            runBlocking { auth.getAccessToken() }        // OkHttp's own thread: blocking is fine here
        } catch (e: AuthException) {
            null
        }
        return chain.proceed(if (token != null) request.newBuilder().header("Authorization", "Bearer $token").build() else request)
    }
}

/**
 * On a 401 of your API, renews the token ONCE (only if the request carried the current token) and retries; gives up
 * otherwise. Pair it with [OpenBackAuthInterceptor].
 */
public class OpenBackAuthAuthenticator(private val auth: OpenBackAuth) : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        if (response.priorResponse != null) return null                    // already retried
        val sent = response.request.header("Authorization")?.removePrefix("Bearer ") ?: return null
        return try {
            val token = runBlocking {
                val current = if (auth.isSignedIn) auth.getAccessToken() else return@runBlocking null
                if (current != sent) current else auth.refresh()          // someone renewed it already, or renew now
            } ?: return null
            response.request.newBuilder().header("Authorization", "Bearer $token").build()
        } catch (e: AuthException) {
            null
        }
    }
}
