// openback-app-auth-cpp -- OpenID Connect helpers: PKCE, authorization request, callback, logout URL.
#include "openback/app_auth/oidc.hpp"

#include <utility>

#include "openback/app_auth/error.hpp"
#include "openback/app_auth/jwt.hpp"
#include "internal.hpp"

namespace openback::app_auth {

using detail::json;

std::string random_url_token(std::size_t random_bytes) { return base64url_encode(detail::random_bytes(random_bytes)); }

std::string generate_code_verifier() { return random_url_token(48); }

std::string code_challenge_s256(std::string_view verifier) { return base64url_encode(detail::sha256(verifier)); }

json AuthorizationRequest::to_json() const {
    json value = json::object();
    value["url"] = url;
    value["state"] = state;
    value["nonce"] = nonce;
    value["code_verifier"] = code_verifier;
    value["redirect_uri"] = redirect_uri;
    return value;
}

AuthorizationRequest AuthorizationRequest::from_json(const json& value) {
    AuthorizationRequest request;
    request.url = detail::string_or(value, "url");
    request.state = detail::string_or(value, "state");
    request.nonce = detail::string_or(value, "nonce");
    request.code_verifier = detail::string_or(value, "code_verifier");
    request.redirect_uri = detail::string_or(value, "redirect_uri");
    return request;
}

AuthorizationRequest build_authorization_request(const std::string& issuer, const std::string& client_id,
                                                 const std::string& redirect_uri, const AuthorizationOptions& options) {
    AuthorizationRequest request;
    request.redirect_uri = options.redirect_uri ? *options.redirect_uri : redirect_uri;
    if (request.redirect_uri.empty()) throw AppAuthError(400, "invalid_request", "A redirect URI is required");
    if (client_id.empty()) throw AppAuthError(400, "invalid_request", "A client ID is required");
    request.state = random_url_token(16);
    request.nonce = random_url_token(16);
    request.code_verifier = generate_code_verifier();

    detail::FormFields query;
    query.emplace_back("response_type", "code");
    query.emplace_back("client_id", client_id);
    query.emplace_back("redirect_uri", request.redirect_uri);
    query.emplace_back("scope", options.scope.empty() ? std::string("openid") : options.scope);
    query.emplace_back("state", request.state);
    query.emplace_back("nonce", request.nonce);
    query.emplace_back("code_challenge", code_challenge_s256(request.code_verifier));
    query.emplace_back("code_challenge_method", "S256");
    if (options.provider) query.emplace_back("provider", *options.provider);
    if (options.org_id) query.emplace_back("org_id", *options.org_id);
    if (options.prompt) query.emplace_back("prompt", *options.prompt);
    if (options.screen_hint) query.emplace_back("screen_hint", *options.screen_hint);
    if (options.login_hint) query.emplace_back("login_hint", *options.login_hint);
    if (options.ui_locales) query.emplace_back("ui_locales", *options.ui_locales);
    if (options.max_age) query.emplace_back("max_age", std::to_string(*options.max_age));
    request.url = detail::strip_trailing_slashes(issuer) + "/authorize?" + detail::form_encode(query);
    return request;
}

std::map<std::string, std::string> parse_query_string(std::string_view query) {
    std::map<std::string, std::string> out;
    if (!query.empty() && query.front() == '?') query.remove_prefix(1);
    std::size_t pos = 0;
    while (pos <= query.size()) {
        std::size_t amp = query.find('&', pos);
        if (amp == std::string_view::npos) amp = query.size();
        const std::string_view pair = query.substr(pos, amp - pos);
        if (!pair.empty()) {
            const std::size_t eq = pair.find('=');
            std::string name = detail::url_decode(pair.substr(0, eq), true);
            std::string value =
                eq == std::string_view::npos ? std::string() : detail::url_decode(pair.substr(eq + 1), true);
            out.emplace(std::move(name), std::move(value));  // the first occurrence wins
        }
        pos = amp + 1;
    }
    return out;
}

CallbackParams CallbackParams::from_query(const std::map<std::string, std::string>& params) {
    CallbackParams out;
    const auto get = [&params](const char* key) -> std::optional<std::string> {
        const auto it = params.find(key);
        if (it == params.end()) return std::nullopt;
        return it->second;
    };
    out.code = get("code");
    out.state = get("state");
    out.iss = get("iss");
    out.error = get("error");
    out.error_description = get("error_description");
    return out;
}

CallbackParams CallbackParams::from_url(std::string_view url) {
    std::string_view fragment;
    const std::size_t hash = url.find('#');
    if (hash != std::string_view::npos) {
        fragment = url.substr(hash + 1);
        url = url.substr(0, hash);
    }
    std::string_view query;
    const std::size_t question = url.find('?');
    if (question != std::string_view::npos) {
        query = url.substr(question + 1);
    } else if (url.find("://") == std::string_view::npos && url.find('=') != std::string_view::npos) {
        query = url;  // a bare query string
    }
    CallbackParams params = from_query(parse_query_string(query));
    if (!params.is_callback() && !fragment.empty()) params = from_query(parse_query_string(fragment));
    return params;
}

std::string validate_callback(const CallbackParams& params, const AuthorizationRequest& transaction,
                              const std::string& issuer) {
    if (params.error) {
        const std::string description =
            params.error_description && !params.error_description->empty() ? *params.error_description : *params.error;
        throw AppAuthError(400, *params.error, description);
    }
    if (!params.code || params.code->empty()) {
        throw AppAuthError(400, "invalid_request", "The callback carries no authorization code");
    }
    if (transaction.state.empty() || !params.state || !detail::constant_time_equals(*params.state, transaction.state)) {
        throw AppAuthError(400, "invalid_state", "Sign-in state mismatch");
    }
    if (params.iss && *params.iss != detail::strip_trailing_slashes(issuer)) {
        throw AppAuthError(400, "invalid_issuer", "Unexpected issuer in the callback");
    }
    return *params.code;
}

std::string build_logout_url(const std::string& issuer, const std::string& client_id, const LogoutOptions& options) {
    detail::FormFields query;
    if (!client_id.empty()) query.emplace_back("client_id", client_id);
    if (options.id_token_hint && !options.id_token_hint->empty()) query.emplace_back("id_token_hint", *options.id_token_hint);
    if (options.post_logout_redirect_uri) query.emplace_back("post_logout_redirect_uri", *options.post_logout_redirect_uri);
    if (options.state) query.emplace_back("state", *options.state);
    std::string url = detail::strip_trailing_slashes(issuer) + "/logout";
    if (!query.empty()) url += "?" + detail::form_encode(query);
    return url;
}

}  // namespace openback::app_auth
