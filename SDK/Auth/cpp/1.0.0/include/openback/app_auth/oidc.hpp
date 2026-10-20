// openback-app-auth-cpp -- OpenID Connect helpers shared by Client (public apps) and OidcWebClient (server apps):
// PKCE S256, the authorization request, the callback, the logout URL.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace openback::app_auth {

/// base64url of `random_bytes` bytes from the OpenSSL CSPRNG (RAND_bytes).
std::string random_url_token(std::size_t random_bytes = 32);

/// A PKCE code verifier: 48 random bytes, base64url (64 characters).
std::string generate_code_verifier();

/// The PKCE S256 challenge of a verifier: base64url(SHA-256(verifier)).
std::string code_challenge_s256(std::string_view verifier);

/// What to ask the hosted sign-in page (all optional).
struct AuthorizationOptions {
    std::optional<std::string> redirect_uri;      // overrides the configured one; must match a registered one exactly
    std::string scope = "openid profile email";   // add "offline_access" if you want it spelled out
    std::optional<std::string> provider;          // go straight to a social provider (its id)
    std::optional<std::string> org_id;            // B2B: the organization to sign in to
    std::optional<std::string> prompt;            // "none" | "login"
    std::optional<std::string> screen_hint;       // "signup"
    std::optional<std::string> login_hint;        // an email to prefill
    std::optional<std::string> ui_locales;        // "it" | "en"
    std::optional<std::int64_t> max_age;          // seconds
};

/// A started sign-in: open `url` in a browser; keep the rest (the "transaction") until the callback.
struct AuthorizationRequest {
    std::string url;
    std::string state;
    std::string nonce;
    std::string code_verifier;                    // secret: never send it anywhere but the token endpoint
    std::string redirect_uri;

    nlohmann::json to_json() const;
    static AuthorizationRequest from_json(const nlohmann::json& value);
};

/// Builds <issuer>/authorize with response_type=code, PKCE S256, a fresh state and nonce.
AuthorizationRequest build_authorization_request(const std::string& issuer, const std::string& client_id,
                                                 const std::string& redirect_uri, const AuthorizationOptions& options = {});

/// The parameters of a redirect back from the hosted page.
struct CallbackParams {
    std::optional<std::string> code;
    std::optional<std::string> state;
    std::optional<std::string> iss;
    std::optional<std::string> error;
    std::optional<std::string> error_description;

    static CallbackParams from_query(const std::map<std::string, std::string>& params);
    /// From a full callback URL ("com.example.app:/callback?code=..&state=.."), a bare query string, or a fragment.
    static CallbackParams from_url(std::string_view url);

    bool is_callback() const noexcept { return code.has_value() || error.has_value(); }
};

/// Parses a query string ("a=1&b=2", '+' as space, percent-decoding). The first occurrence of a name wins.
std::map<std::string, std::string> parse_query_string(std::string_view query);

/// Checks a callback against its transaction and returns the authorization code. Throws AppAuthError (status 400):
/// the OAuth error of the redirect (e.g. "login_required", "access_denied"), "invalid_request" (no code),
/// "invalid_state" (state mismatch, compared in constant time), "invalid_issuer" (iss present and not the issuer).
std::string validate_callback(const CallbackParams& params, const AuthorizationRequest& transaction,
                              const std::string& issuer);

struct LogoutOptions {
    std::optional<std::string> id_token_hint;
    std::optional<std::string> post_logout_redirect_uri;  // must be a registered post-logout redirect URI
    std::optional<std::string> state;
};

/// <issuer>/logout?client_id=..&id_token_hint=..&post_logout_redirect_uri=..&state=..
std::string build_logout_url(const std::string& issuer, const std::string& client_id, const LogoutOptions& options = {});

}  // namespace openback::app_auth
