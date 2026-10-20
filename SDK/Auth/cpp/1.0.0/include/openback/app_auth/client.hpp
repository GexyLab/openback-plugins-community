// openback-app-auth-cpp -- Client: an app (desktop, CLI, device, or a server calling the pool for its users) signed in
// to an OpenBack user pool. Synchronous: every call blocks until the pool answers; results are returned, failures are
// thrown as AppAuthError. Thread-safe: one Client may be shared by all the threads of the app.
//
//   openback::app_auth::Client auth("https://api.example.com/gateway/shop/auth/main", "uapp_...");
//   auto res = auth.sign_in_with_password("ada@example.com", password);
//   if (res.status == OutcomeStatus::MfaRequired) res = auth.verify_mfa(*res.mfa_token, code);
//   std::string token = auth.get_access_token();     // renewed one minute before it expires
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "openback/app_auth/error.hpp"
#include "openback/app_auth/http.hpp"
#include "openback/app_auth/oidc.hpp"
#include "openback/app_auth/storage.hpp"
#include "openback/app_auth/types.hpp"

namespace openback::app_auth {

struct ClientOptions {
    /// Default redirect URI of the hosted sign-in (build_authorization_request).
    std::optional<std::string> redirect_uri;
    /// Where the session is kept. Default: a MemoryTokenStorage (lost when the process ends).
    std::shared_ptr<TokenStorage> storage;
    /// The storage key. Default: "openback.auth.<client id>".
    std::optional<std::string> storage_key;
    /// The HTTP layer. Default: default_transport() (libcurl).
    std::shared_ptr<HttpTransport> http;
    /// Only for "web" / "backend" apps exchanging a code at the token endpoint. Never put a secret in a public app.
    std::optional<std::string> client_secret;
    /// With client_secret: true = client_secret_basic (default), false = client_secret_post.
    bool client_secret_basic = true;
    /// Timeout of each request.
    std::chrono::milliseconds timeout{30000};
    /// Source of the current time (tests).
    ClockFn clock;
};

struct SignUpParams {
    std::string email;
    std::string password;
    std::string display_name;
    std::optional<std::string> locale;            // "it" | "en"
    std::optional<std::string> org_id;
};

struct EmailCodeParams {
    std::optional<std::string> email;             // with code
    std::optional<std::string> code;
    std::optional<std::string> token;             // or the token of the email link
    std::optional<std::string> org_id;
};

struct ResetPasswordParams {
    std::optional<std::string> token;             // the token of the email link, or
    std::optional<std::string> email;             // email + code
    std::optional<std::string> code;
    std::string new_password;
};

struct VerifyEmailParams {
    std::optional<std::string> token;             // the token of the email link, or
    std::optional<std::string> email;             // email + code
    std::optional<std::string> code;
};

struct ProfileUpdate {
    std::optional<std::string> display_name;
    std::optional<std::string> photo_url;
    std::optional<std::string> locale;
};

struct EmailChangeConfirmation {
    std::optional<std::string> code;
    std::optional<std::string> token;
};

/// Called with the signed-in user and organization (both empty when signed out).
using AuthStateListener = std::function<void(const std::optional<PoolUser>& user, const std::optional<ActiveOrg>& org)>;

class Client {
public:
    /// issuer: the pool's address (a trailing slash is removed); client_id: the app's "uapp_..." id.
    Client(std::string issuer, std::string client_id, ClientOptions options = {});
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;

    const std::string& issuer() const noexcept;
    const std::string& client_id() const noexcept;

    /// GET /config: methods, providers, password policy, MFA mode, branding.
    nlohmann::json config();

    // --- state ------------------------------------------------------------------------------------------------------
    std::optional<PoolUser> current_user() const;
    std::optional<ActiveOrg> current_org() const;
    /// The claims of the stored access token, decoded and NOT verified (display only).
    std::optional<nlohmann::json> access_token_claims() const;
    bool is_signed_in() const;
    /// Registers a listener, calls it at once with the current state; the returned function unregisters it.
    /// Listeners run on the thread that changed the state, never while the Client holds its lock.
    std::function<void()> on_auth_state_changed(AuthStateListener listener);

    // --- tokens -----------------------------------------------------------------------------------------------------
    /// The access token, renewed when it expires in 60 seconds or less (one refresh at a time).
    std::string get_access_token();
    /// Renews the tokens now (optionally into another organization); concurrent calls share one request.
    /// A 401 ends the session locally. A network error is thrown and never retried automatically.
    std::string refresh(const std::optional<std::string>& org_id = std::nullopt);
    /// Sends `request` with "Authorization: Bearer <access token>" (for your own API).
    HttpResponse authorized_request(HttpRequest request);

    // --- sign-up and sign-in ----------------------------------------------------------------------------------------
    Outcome sign_up(const SignUpParams& params);
    Outcome sign_in_with_password(const std::string& email, const std::string& password,
                                  const std::optional<std::string>& org_id = std::nullopt);
    nlohmann::json send_email_code(const std::string& email);
    Outcome sign_in_with_email_code(const EmailCodeParams& params);
    Outcome sign_in_anonymously();
    Outcome verify_mfa(const std::string& mfa_token, const std::string& code);
    /// With an mfa_token (sign-in requiring enrollment) or signed in (no token).
    MfaEnrollment enroll_mfa(const std::optional<std::string>& mfa_token = std::nullopt);
    MfaConfirmation confirm_mfa(const std::string& code, const std::optional<std::string>& mfa_token = std::nullopt);
    nlohmann::json disable_mfa(const std::string& code);

    // --- passwords and emails ---------------------------------------------------------------------------------------
    nlohmann::json send_password_reset(const std::string& email);
    nlohmann::json reset_password(const ResetPasswordParams& params);
    nlohmann::json change_forced_password(const std::string& change_token, const std::string& new_password);
    nlohmann::json verify_email(const VerifyEmailParams& params);
    nlohmann::json resend_verification();

    // --- the signed-in user -----------------------------------------------------------------------------------------
    PoolUser me();
    PoolUser update_profile(const ProfileUpdate& update);
    /// Every session of the user ends: the local one is cleared (sign in again).
    nlohmann::json change_password(const std::optional<std::string>& current_password, const std::string& new_password);
    nlohmann::json change_email(const std::string& new_email);
    nlohmann::json confirm_email_change(const EmailChangeConfirmation& confirmation);
    nlohmann::json upgrade_anonymous(const std::string& email, const std::string& password);
    /// Deletes the account and clears the local session.
    nlohmann::json delete_account(const std::optional<std::string>& password = std::nullopt);
    /// Best-effort server sign-out (revokes the refresh token; everywhere = every session of the user), then always
    /// clears the local session. Never throws because of the server.
    void sign_out(bool everywhere = false);

    // --- organizations (B2B pools) ----------------------------------------------------------------------------------
    OrganizationList organizations();
    Organization create_organization(const std::string& name);
    /// New tokens for that organization (shares the single-flight lock with refresh).
    std::optional<ActiveOrg> switch_organization(const std::string& org_id);
    MemberPage members(const std::string& org_id, const MemberQuery& query = {});
    nlohmann::json add_member(const std::string& org_id, const NewMember& member);
    nlohmann::json set_member_roles(const std::string& org_id, const std::string& user_id,
                                    const std::vector<std::string>& roles);
    nlohmann::json remove_member(const std::string& org_id, const std::string& user_id);

    // --- hosted sign-in (OpenID Connect, code + PKCE S256) ----------------------------------------------------------
    /// Builds the authorization URL and stores the transaction (state, nonce, verifier) under "<storage key>.pkce".
    /// Open `url` in the system browser; the pool redirects to the redirect URI with the code.
    AuthorizationRequest build_authorization_request(const AuthorizationOptions& options = {});
    /// Completes the sign-in from the redirect URL: checks error, state and iss, exchanges the code (PKCE), checks the
    /// ID token's nonce, keeps the session and loads the user (nullopt if GET /me failed: the session is kept anyway).
    /// Throws AppAuthError "invalid_request" when the URL is not a callback.
    std::optional<PoolUser> handle_redirect_callback(const std::string& callback_url);
    /// <issuer>/logout for the stored ID token (does not sign out locally).
    std::string build_logout_url(const std::optional<std::string>& post_logout_redirect_uri = std::nullopt,
                                 const std::optional<std::string>& state = std::nullopt) const;
    /// sign_out() and the logout URL to open in the browser (ends the hosted page's session too).
    std::string sign_out_redirect(const std::optional<std::string>& post_logout_redirect_uri = std::nullopt,
                                  const std::optional<std::string>& state = std::nullopt);

    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

}  // namespace openback::app_auth
