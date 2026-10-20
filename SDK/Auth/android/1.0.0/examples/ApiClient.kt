package com.example.app

import io.openback.appauth.android.OpenBackAuth
import io.openback.appauth.android.OpenBackAuthAuthenticator
import io.openback.appauth.android.OpenBackAuthInterceptor
import okhttp3.OkHttpClient
import okhttp3.Request

/** Your API's OkHttpClient: the access token only goes to your API's host. */
class ApiClient(auth: OpenBackAuth) {
    private val http = OkHttpClient.Builder()
        .addInterceptor(OpenBackAuthInterceptor(auth) { it.url.host == "api.example.com" })
        .authenticator(OpenBackAuthAuthenticator(auth))     // one renewal + retry on a 401
        .build()

    /** Call from a background thread / Dispatchers.IO. */
    fun orders(): String = http.newCall(Request.Builder().url("https://api.example.com/gateway/shop/orders").build())
        .execute().use { it.body?.string() ?: "" }
}
