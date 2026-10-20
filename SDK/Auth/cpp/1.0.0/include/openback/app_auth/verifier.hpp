// openback-app-auth-cpp -- TokenVerifier: checks the pool's access tokens (and ID tokens) locally, with the pool's
// public keys (JWKS). No call to OpenBack per token: the keys are cached.
//
//   VerifierOptions options;
//   options.audiences = {"uapp_..."};
//   TokenVerifier verifier("https://api.example.com/gateway/shop/auth/main", options);
//   AppUser user = verifier.verify(token);            // throws TokenVerificationError
//
// Access tokens cannot be revoked before they expire (default lifetime 15 minutes): a signed-out user's token stays
// valid until then. Keep the pool's access token lifetime short.
#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "openback/app_auth/error.hpp"
#include "openback/app_auth/http.hpp"
#include "openback/app_auth/types.hpp"

namespace openback::app_auth {

struct VerifierOptions {
    /// The client IDs whose tokens are accepted (the token's "aud"). Required.
    std::vector<std::string> audiences;
    /// Default: <issuer>/.well-known/jwks.json.
    std::optional<std::string> jwks_uri;
    /// How long the keys are used before they are fetched again.
    std::chrono::seconds jwks_cache_ttl{600};
    /// An unknown "kid" fetches the keys again at most once in this interval.
    std::chrono::seconds unknown_kid_refetch_interval{30};
    /// Tolerance on exp / nbf / iat.
    std::chrono::seconds leeway{60};
    /// The HTTP layer. Default: default_transport() (libcurl).
    std::shared_ptr<HttpTransport> http;
    std::chrono::milliseconds timeout{10000};
    ClockFn clock;
};

/// The user behind a verified access token.
struct AppUser {
    std::string id;                               // sub (usr_...)
    std::string pool_id;                          // pool
    std::string client_id;                        // aud
    std::optional<std::string> email;
    bool email_verified = false;
    bool anonymous = false;                       // anon: a guest
    std::optional<std::string> org_id;
    std::vector<std::string> roles;
    std::vector<std::string> permissions;         // "*" = all
    nlohmann::json attributes = nlohmann::json::object();  // attr
    std::optional<std::string> session_id;        // sid
    std::vector<std::string> amr;
    nlohmann::json claims = nlohmann::json::object();      // every claim, raw

    bool has_role(std::string_view role) const;
    /// True if permissions contains `permission` or "*".
    bool has_permission(std::string_view permission) const;

    static AppUser from_claims(const nlohmann::json& claims);
};

/// Thread-safe; copies share the key cache.
class TokenVerifier {
public:
    /// Throws std::invalid_argument when options.audiences is empty.
    TokenVerifier(std::string issuer, VerifierOptions options);

    const std::string& issuer() const noexcept;

    /// Verifies an access token (ES256 only, typ at+jwt, iss, aud, exp/nbf/iat with leeway, signature).
    /// Throws TokenVerificationError (401) when it is refused, AppAuthError{503, "jwks_unavailable"} when the keys
    /// could not be fetched at all.
    AppUser verify(std::string_view access_token) const;
    /// Same checks; returns the raw claims.
    nlohmann::json verify_access_token_claims(std::string_view access_token) const;
    /// Verifies an ID token (typ JWT or absent, aud = one of the audiences) and, if given, its nonce.
    nlohmann::json verify_id_token(std::string_view id_token,
                                   const std::optional<std::string>& expected_nonce = std::nullopt) const;

    /// Loads keys from a JWKS document (e.g. to start offline); later fetches replace them.
    void set_jwks(const nlohmann::json& jwks) const;
    /// Fetches the keys now. Throws AppAuthError{503, "jwks_unavailable"} on failure.
    void refresh_jwks() const;

    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

}  // namespace openback::app_auth
