package com.example.app

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.openback.appauth.android.AuthException
import io.openback.appauth.android.AuthOutcome
import io.openback.appauth.android.AuthState
import io.openback.appauth.android.AuthorizationOptions
import io.openback.appauth.android.BrowserResult
import io.openback.appauth.android.OpenBackSignInContract
import io.openback.appauth.android.OpenBackSignOutContract
import kotlinx.coroutines.launch

/**
 * Example screen (needs androidx.lifecycle:lifecycle-runtime-ktx in the app). The client lives in the Application:
 *
 *   class App : Application() {
 *       val auth by lazy {
 *           OpenBackAuth.create(this, "https://api.example.com/gateway/shop/auth/main", "uapp_your_android_app",
 *               redirectUri = "com.example.app:/oauth2redirect")
 *       }
 *   }
 */
class SignInActivity : ComponentActivity() {
    private val auth get() = (application as App).auth

    // Hosted page in a Custom Tab; the pool redirects to com.example.app:/oauth2redirect
    private val signIn = registerForActivityResult(OpenBackSignInContract()) { result ->
        when (result) {
            is BrowserResult.Redirected -> lifecycleScope.launch {
                try {
                    auth.handleRedirectCallback(result.uri)
                } catch (e: AuthException) {
                    toast("Sign-in failed: ${e.code}")                 // never log tokens or codes
                }
            }
            BrowserResult.Cancelled -> toast("Sign-in cancelled")
            BrowserResult.NoBrowser -> toast("Install a web browser to sign in")
        }
    }

    private val signOut = registerForActivityResult(OpenBackSignOutContract()) { /* already signed out locally */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                auth.authState.collect { state ->
                    when (state) {
                        is AuthState.SignedIn -> showHome(state.user?.displayName)
                        AuthState.SignedOut -> showSignIn()
                    }
                }
            }
        }
    }

    fun onHostedSignInClicked(provider: String? = null) {
        lifecycleScope.launch { signIn.launch(auth.buildAuthorizationRequest(AuthorizationOptions(provider = provider))) }
    }

    fun onPasswordSignInClicked(email: String, password: String) {
        lifecycleScope.launch {
            try {
                when (val res = auth.signInWithPassword(email, password)) {
                    is AuthOutcome.SignedIn -> Unit                      // authState moves to SignedIn
                    is AuthOutcome.MfaRequired -> askCode { code -> lifecycleScope.launch { auth.verifyMfa(res.mfaToken, code) } }
                    is AuthOutcome.MfaEnrollRequired -> {
                        val enrollment = auth.enrollMfa(res.mfaToken)    // show enrollment.otpauthUri as a QR code
                        askCode { code -> lifecycleScope.launch { auth.confirmMfa(code, res.mfaToken) } }
                    }
                    is AuthOutcome.PasswordChangeRequired -> askNewPassword { pw ->
                        lifecycleScope.launch { auth.changeForcedPassword(res.changeToken, pw) }
                    }
                    is AuthOutcome.VerificationRequired -> toast("Check your inbox to verify the address")
                    is AuthOutcome.Unknown -> toast("Unexpected answer: ${res.status}")
                }
            } catch (e: AuthException) {
                toast(if (e.code == "invalid_credentials") "Wrong email or password" else "Error: ${e.code}")
            }
        }
    }

    fun onSignOutClicked() {
        lifecycleScope.launch { signOut.launch(auth.signOutRedirect(postLogoutRedirectUri = "com.example.app:/signed-out")) }
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    private fun showHome(name: String?) { /* ... */ }
    private fun showSignIn() { /* ... */ }
    private fun askCode(onCode: (String) -> Unit) { /* ... */ }
    private fun askNewPassword(onPassword: (String) -> Unit) { /* ... */ }
}
