// openback-app-auth-cpp -- OidcWebClient: authorization code flow for confidential "web" apps.
#include "openback/app_auth/web_client.hpp"

#include <stdexcept>
#include <utility>

#include "internal.hpp"

namespace openback::app_auth {

using detail::json;

struct OidcWebClient::Impl {
    std::string issuer;
    std::string client_id;
    OidcWebClientOptions options;
    std::shared_ptr<HttpTransport> http;
    std::shared_ptr<TokenVerifier> verifier;

    detail::ClientCredentials credentials() const {
        return detail::ClientCredentials{client_id, options.client_secret,
                                         options.auth_method == ClientAuthMethod::ClientSecretBasic};
    }

    CallbackResult complete(const CallbackParams& params, const AuthorizationRequest& transaction) const {
        const std::string code = validate_callback(params, transaction, issuer);
        detail::FormFields form;
        form.emplace_back("grant_type", "authorization_code");
        form.emplace_back("code", code);
        form.emplace_back("redirect_uri", transaction.redirect_uri);
        form.emplace_back("code_verifier", transaction.code_verifier);
        const json data = detail::post_form(*http, issuer + "/token", std::move(form), credentials(), options.timeout);
        CallbackResult result;
        result.tokens = TokenSet::from_json(data);
        if (result.tokens.access_token.empty()) {
            throw AppAuthError(502, "invalid_response", "The token endpoint answered without an access token");
        }
        if (result.tokens.id_token) {
            result.id_token_claims = verifier->verify_id_token(*result.tokens.id_token, transaction.nonce);
        } else {
            result.id_token_claims = nullptr;
        }
        return result;
    }
};

OidcWebClient::OidcWebClient(std::string issuer, std::string client_id, OidcWebClientOptions options) {
    auto impl = std::make_shared<Impl>();
    impl->issuer = detail::strip_trailing_slashes(std::move(issuer));
    impl->client_id = std::move(client_id);
    if (impl->issuer.empty() || impl->client_id.empty()) {
        throw std::invalid_argument("openback::app_auth::OidcWebClient: issuer and client_id are required");
    }
    if (options.client_secret.empty()) {
        throw std::invalid_argument("openback::app_auth::OidcWebClient: client_secret is required (web apps are confidential)");
    }
    impl->http = options.http ? options.http : default_transport();
    if (options.verifier) {
        impl->verifier = options.verifier;
    } else {
        VerifierOptions verifier_options;
        verifier_options.audiences = {impl->client_id};
        verifier_options.http = impl->http;
        impl->verifier = std::make_shared<TokenVerifier>(impl->issuer, std::move(verifier_options));
    }
    impl->options = std::move(options);
    impl_ = std::move(impl);
}

const std::string& OidcWebClient::issuer() const noexcept { return impl_->issuer; }
const std::string& OidcWebClient::client_id() const noexcept { return impl_->client_id; }
std::shared_ptr<TokenVerifier> OidcWebClient::verifier() const { return impl_->verifier; }

AuthorizationRequest OidcWebClient::authorization_url(const AuthorizationOptions& options) const {
    const std::string redirect = options.redirect_uri ? *options.redirect_uri : impl_->options.redirect_uri;
    return ::openback::app_auth::build_authorization_request(impl_->issuer, impl_->client_id, redirect, options);
}

CallbackResult OidcWebClient::handle_callback(const std::map<std::string, std::string>& params,
                                              const AuthorizationRequest& transaction) const {
    return impl_->complete(CallbackParams::from_query(params), transaction);
}

CallbackResult OidcWebClient::handle_callback_url(std::string_view callback_url,
                                                  const AuthorizationRequest& transaction) const {
    return impl_->complete(CallbackParams::from_url(callback_url), transaction);
}

TokenSet OidcWebClient::refresh(const std::string& refresh_token, const std::optional<std::string>& org_id) const {
    detail::FormFields form;
    form.emplace_back("grant_type", "refresh_token");
    form.emplace_back("refresh_token", refresh_token);
    if (org_id) form.emplace_back("org_id", *org_id);
    const json data =
        detail::post_form(*impl_->http, impl_->issuer + "/token", std::move(form), impl_->credentials(), impl_->options.timeout);
    TokenSet tokens = TokenSet::from_json(data);
    if (tokens.access_token.empty()) {
        throw AppAuthError(502, "invalid_response", "The token endpoint answered without an access token");
    }
    return tokens;
}

void OidcWebClient::revoke(const std::string& refresh_token) const {
    detail::FormFields form;
    form.emplace_back("token", refresh_token);
    form.emplace_back("token_type_hint", "refresh_token");
    detail::post_form(*impl_->http, impl_->issuer + "/revoke", std::move(form), impl_->credentials(),
                      impl_->options.timeout);
}

json OidcWebClient::userinfo(const std::string& access_token) const {
    HttpRequest request;
    request.method = "GET";
    request.url = impl_->issuer + "/userinfo";
    request.timeout = impl_->options.timeout;
    request.headers.emplace_back("Accept", "application/json");
    request.headers.emplace_back("Authorization", "Bearer " + access_token);
    const HttpResponse response = detail::send_checked(*impl_->http, request);
    if (!response.ok()) throw detail::error_from_response(response);
    json data = detail::parse_json_or_null(response.body);
    if (!data.is_object()) throw AppAuthError(502, "invalid_response", "The userinfo endpoint answered without JSON");
    return data;
}

std::string OidcWebClient::logout_url(const LogoutOptions& options) const {
    return ::openback::app_auth::build_logout_url(impl_->issuer, impl_->client_id, options);
}

}  // namespace openback::app_auth
