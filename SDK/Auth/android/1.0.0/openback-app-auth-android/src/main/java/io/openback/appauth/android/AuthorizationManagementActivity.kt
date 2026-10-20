package io.openback.appauth.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent

/**
 * Internal: holds the place of the app while the hosted page is open in a Custom Tab (the AppAuth pattern).
 *
 * 1. started for a result with the URL to open → opens the Custom Tab;
 * 2. the pool redirects to the app's scheme → [RedirectReceiverActivity] → brought back here with the URI (onNewIntent)
 *    → result OK with the URI;
 * 3. the user closed the tab (the activity resumes with no URI) → result CANCELED.
 */
public class AuthorizationManagementActivity : Activity() {
    private var browserStarted = false
    private var url: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val source = savedInstanceState ?: intent.extras
        url = source?.getString(EXTRA_URL)
        browserStarted = savedInstanceState?.getBoolean(KEY_STARTED, false) ?: false
        if (url == null && intent.data == null) {
            finishWith(RESULT_CANCELED, null)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        val response = intent.data
        if (response != null) {
            finishWith(RESULT_OK, Intent().setData(response))
            return
        }
        if (!browserStarted) {
            browserStarted = true
            try {
                CustomTabsIntent.Builder()
                    .setShowTitle(true)
                    .setUrlBarHidingEnabled(false)
                    .build()
                    .launchUrl(this, Uri.parse(url))
            } catch (e: ActivityNotFoundException) {
                finishWith(RESULT_CANCELED, Intent().putExtra(EXTRA_ERROR, ERROR_NO_BROWSER))
            }
            return
        }
        finishWith(RESULT_CANCELED, null)                   // back from the tab without a redirect
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(EXTRA_URL, url)
        outState.putBoolean(KEY_STARTED, browserStarted)
    }

    private fun finishWith(code: Int, data: Intent?) {
        setResult(code, data)
        finish()
        overridePendingTransitionCompat()
    }

    @Suppress("DEPRECATION")
    private fun overridePendingTransitionCompat() {
        overridePendingTransition(0, 0)
    }

    internal companion object {
        const val EXTRA_URL = "io.openback.appauth.url"
        const val EXTRA_ERROR = "io.openback.appauth.error"
        const val ERROR_NO_BROWSER = "no_browser"
        private const val KEY_STARTED = "io.openback.appauth.started"

        fun startIntent(context: Context, url: String): Intent =
            Intent(context, AuthorizationManagementActivity::class.java).putExtra(EXTRA_URL, url)

        fun responseIntent(context: Context, response: Uri): Intent =
            Intent(context, AuthorizationManagementActivity::class.java)
                .setData(response)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
}
