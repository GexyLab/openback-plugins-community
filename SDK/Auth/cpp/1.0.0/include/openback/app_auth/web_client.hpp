// openback-app-auth-cpp -- OidcWebClient: the hosted sign-in for a "web" app (a confidential app with its own server).
// The server builds the authorization URL, keeps the transaction in the user's (server-side) session, handles the
// callback, and holds the tokens.
//
//   OidcWebClientOptions o; o.client_secret = secret_from_your_vault; o.redirect_uri = "https://app.example.com/callback";
//   OidcWebClient oidc(issuer, "uapp_...", o);
//   AuthorizationRequest tx = oidc.authorization_url();       // store tx.to_json() in the session, redirect to tx.url
//   CallbackResult r = oidc.handle_callback(query_params, tx); // r.tokens, r.id_token_claims (verified)
#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "openback/app_auth/error.hpp"
#include "openback/app_auth/http.hpp"
#include "openback/app_auth/oidc.hpp"
#include "openback/app_auth/types.hpp"
#include "openback/app_auth/verifier.hpp"

namespace openback::app_auth {

enum class ClientAuthMethod {
    ClientSecretBasic,   // Authorization: Basic base64(urlencode(id):urlencode(secret)) -- default
    ClientSecretPost     // client_id + client_secret in the form
};

struct OidcWebClientOptions {
    /// The app's client secret (keep it out of source code and logs).
    std::string client_secret;
    /// The default redirect URI (registered in the app).
    std::string redirect_uri;
    ClientAuthMethod auth_method = ClientAuthMethod::ClientSecretBasic;
    /// The HTTP layer. Default: default_transport() (libcurl).
    std::shared_ptr<HttpTransport> http;
    /// Verifies the ID tokens. Default: a TokenVerifier for this issuer and client ID on the same transport.
    std::shared_ptr<TokenVerifier> verifier;
    std::chrono::milliseconds timeout{30000};
};

struct CallbackResult {
    TokenSet tokens;
    /// The verified ID token's claims (null when the answer had no ID token, i.e. without the "openid" scope).
    nlohmann::json id_token_claims;
};

class OidcWebClient {
public:
    OidcWebClient(std::string issuer, std::string client_id, OidcWebClientOptions options);

    const std::string& issuer() const noexcept;
    const std::string& client_id() const noexcept;
    std::shared_ptr<TokenVerifier> verifier() const;

    /// The authorization URL + the transaction (state, nonce, code_verifier, redirect_uri) to keep in the session.
    AuthorizationRequest authorization_url(const AuthorizationOptions& options = {}) const;
    /// The callback's query parameters (code, state, iss | error, error_description) and the stored transaction:
    /// checks them, exchanges the code (PKCE + client authentication), verifies the ID token and its nonce.
    CallbackResult handle_callback(const std::map<std::string, std::string>& params,
                                   const AuthorizationRequest& transaction) const;
    /// Same, from the full callback URL (or its query string).
    CallbackResult handle_callback_url(std::string_view callback_url, const AuthorizationRequest& transaction) const;
    /// New tokens (the refresh token rotates: store the new one; one refresh at a time per session).
    TokenSet refresh(const std::string& refresh_token, const std::optional<std::string>& org_id = std::nullopt) const;
    /// RFC 7009: revokes a refresh token (and its whole family).
    void revoke(const std::string& refresh_token) const;
    /// GET /userinfo with the access token.
    nlohmann::json userinfo(const std::string& access_token) const;
    /// <issuer>/logout?client_id=..
    std::string logout_url(const LogoutOptions& options = {}) const;

    struct Impl;

private:
    std::shared_ptr<const Impl> impl_;
};

}  // namespace openback::app_auth
