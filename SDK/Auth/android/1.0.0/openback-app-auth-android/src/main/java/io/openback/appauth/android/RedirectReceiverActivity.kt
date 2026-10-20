package io.openback.appauth.android

import android.app.Activity
import android.os.Bundle

/**
 * Receives the pool's redirect (`<scheme>:/...?code=..&state=..`, the scheme set by the manifest placeholder
 * `openbackAppAuthRedirectScheme`) and hands it to [AuthorizationManagementActivity], which returns it to the app.
 * It does nothing else: the callback is checked by [OpenBackAuth.handleRedirectCallback] against the pending request.
 */
public class RedirectReceiverActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent?.data
        if (data != null) {
            startActivity(AuthorizationManagementActivity.responseIntent(this, data))
        }
        finish()
    }
}
