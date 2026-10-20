package io.openback.appauth.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContract

/** The result of a browser step (hosted sign-in or sign-out in a Custom Tab). */
public sealed class BrowserResult {
    /** The pool redirected back to the app: pass [uri] to [OpenBackAuth.handleRedirectCallback] (sign-in). */
    public data class Redirected(val uri: String) : BrowserResult()

    /** The user closed the tab (or pressed back) before the redirect. */
    public object Cancelled : BrowserResult() {
        override fun toString(): String = "Cancelled"
    }

    /** No browser able to open the page is installed. */
    public object NoBrowser : BrowserResult() {
        override fun toString(): String = "NoBrowser"
    }
}

internal fun parseBrowserResult(resultCode: Int, intent: Intent?): BrowserResult {
    val data = intent?.data
    return when {
        resultCode == Activity.RESULT_OK && data != null -> BrowserResult.Redirected(data.toString())
        intent?.getStringExtra(AuthorizationManagementActivity.EXTRA_ERROR) == AuthorizationManagementActivity.ERROR_NO_BROWSER -> BrowserResult.NoBrowser
        else -> BrowserResult.Cancelled
    }
}

/**
 * Opens the hosted sign-in page in a Custom Tab and returns the redirect.
 *
 * ```
 * private val signIn = registerForActivityResult(OpenBackSignInContract()) { result ->
 *     if (result is BrowserResult.Redirected) lifecycleScope.launch { auth.handleRedirectCallback(result.uri) }
 * }
 * lifecycleScope.launch { signIn.launch(auth.buildAuthorizationRequest()) }
 * ```
 */
public class OpenBackSignInContract : ActivityResultContract<AuthorizationRequest, BrowserResult>() {
    override fun createIntent(context: Context, input: AuthorizationRequest): Intent =
        AuthorizationManagementActivity.startIntent(context, input.url)

    override fun parseResult(resultCode: Int, intent: Intent?): BrowserResult = parseBrowserResult(resultCode, intent)
}

/**
 * Opens the end-session URL ([OpenBackAuth.signOutRedirect]) in a Custom Tab. With a registered post-logout redirect
 * URI on the app's scheme the tab closes by itself ([BrowserResult.Redirected]); otherwise the user closes it
 * ([BrowserResult.Cancelled]). The local session is already cleared either way.
 */
public class OpenBackSignOutContract : ActivityResultContract<String, BrowserResult>() {
    override fun createIntent(context: Context, input: String): Intent =
        AuthorizationManagementActivity.startIntent(context, input)

    override fun parseResult(resultCode: Int, intent: Intent?): BrowserResult = parseBrowserResult(resultCode, intent)
}
