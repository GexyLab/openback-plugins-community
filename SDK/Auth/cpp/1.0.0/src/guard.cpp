// openback-app-auth-cpp -- BearerGuard: the decision of an HTTP middleware.
#include "openback/app_auth/guard.hpp"

#include <algorithm>
#include <utility>

#include "internal.hpp"

namespace openback::app_auth {

namespace {

bool is_space(char c) noexcept { return c == ' ' || c == '\t'; }

std::string_view trim(std::string_view text) {
    while (!text.empty() && is_space(text.front())) text.remove_prefix(1);
    while (!text.empty() && is_space(text.back())) text.remove_suffix(1);
    return text;
}

GuardResult refusal(int status, const char* error, std::string reason) {
    GuardResult result;
    result.allowed = false;
    result.status = status;
    result.error = error;
    result.reason = std::move(reason);
    result.headers.emplace_back("Content-Type", "application/json");
    result.headers.emplace_back("Cache-Control", "no-store");
    if (status == 401) {
        result.headers.emplace_back("WWW-Authenticate", "Bearer error=\"invalid_token\"");
    } else if (status == 403) {
        result.headers.emplace_back("WWW-Authenticate", "Bearer error=\"insufficient_scope\"");
    }
    nlohmann::json body = nlohmann::json::object();
    body["error"] = error;
    result.body = body.dump();
    return result;
}

}  // namespace

std::optional<std::string> extract_bearer_token(std::string_view authorization_header) {
    const std::string_view header = trim(authorization_header);
    if (header.size() < 8 || !detail::iequals(header.substr(0, 6), "Bearer") || !is_space(header[6])) {
        return std::nullopt;
    }
    const std::string_view token = trim(header.substr(7));
    if (token.empty() || std::any_of(token.begin(), token.end(), is_space)) return std::nullopt;
    return std::string(token);
}

BearerGuard::BearerGuard(TokenVerifier verifier, GuardOptions options)
    : verifier_(std::move(verifier)), options_(std::move(options)) {}

GuardResult BearerGuard::check(std::string_view authorization_header) const {
    const std::optional<std::string> token = extract_bearer_token(authorization_header);
    if (!token) return refusal(401, "invalid_token", "missing bearer token");
    AppUser user;
    try {
        user = verifier_.verify(*token);
    } catch (const TokenVerificationError& e) {
        return refusal(401, "invalid_token", e.reason());
    } catch (const AppAuthError& e) {
        return refusal(503, "temporarily_unavailable", e.code());
    }
    if (user.anonymous && !options_.allow_anonymous) return refusal(403, "insufficient_scope", "anonymous user");
    if (options_.require_verified_email && !user.email_verified) {
        return refusal(403, "insufficient_scope", "email not verified");
    }
    if (!options_.require_roles.empty() &&
        std::none_of(options_.require_roles.begin(), options_.require_roles.end(),
                     [&user](const std::string& role) { return user.has_role(role); })) {
        return refusal(403, "insufficient_scope", "missing role");
    }
    for (const auto& permission : options_.require_permissions) {
        if (!user.has_permission(permission)) return refusal(403, "insufficient_scope", "missing permission");
    }
    GuardResult result;
    result.allowed = true;
    result.status = 200;
    result.user = std::move(user);
    return result;
}

}  // namespace openback::app_auth
