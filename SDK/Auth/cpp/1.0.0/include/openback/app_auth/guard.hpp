// openback-app-auth-cpp -- BearerGuard: the framework-independent part of an HTTP middleware. Give it the request's
// Authorization header; it answers what to do: go on with the AppUser, or the status / headers / JSON body to send.
//
//   BearerGuard guard(verifier, GuardOptions{{"admin"}});
//   GuardResult r = guard.check(request_authorization_header);
//   if (!r) return respond(r.status, r.headers, r.body);   // 401 / 403 / 503
//   handle(*r.user);
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openback/app_auth/http.hpp"
#include "openback/app_auth/verifier.hpp"

namespace openback::app_auth {

struct GuardOptions {
    /// At least one of these roles (empty: no requirement).
    std::vector<std::string> require_roles;
    /// All of these permissions ("*" in the token grants all).
    std::vector<std::string> require_permissions;
    bool require_verified_email = false;
    /// Guest tokens (anon: true) are refused unless true.
    bool allow_anonymous = false;
};

struct GuardResult {
    bool allowed = false;
    /// 200 when allowed; 401 (missing / invalid token), 403 (options not met), 503 (keys unavailable).
    int status = 401;
    /// To send with a refusal (WWW-Authenticate on 401, Content-Type).
    HttpHeaders headers;
    /// JSON body of a refusal: {"error":"invalid_token"} | {"error":"insufficient_scope"} |
    /// {"error":"temporarily_unavailable"}.
    std::string body;
    /// "invalid_token", "insufficient_scope", "temporarily_unavailable"; empty when allowed.
    std::string error;
    /// Why (for your logs; never contains the token).
    std::string reason;
    std::optional<AppUser> user;

    explicit operator bool() const noexcept { return allowed; }
};

/// The token of an "Authorization: Bearer <token>" header value (scheme case-insensitive), nullopt otherwise.
std::optional<std::string> extract_bearer_token(std::string_view authorization_header);

class BearerGuard {
public:
    explicit BearerGuard(TokenVerifier verifier, GuardOptions options = {});

    /// authorization_header: the value of the request's Authorization header ("" when absent).
    GuardResult check(std::string_view authorization_header) const;

    const GuardOptions& options() const noexcept { return options_; }

private:
    TokenVerifier verifier_;
    GuardOptions options_;
};

}  // namespace openback::app_auth
