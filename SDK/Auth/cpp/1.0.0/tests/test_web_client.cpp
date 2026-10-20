#include <catch2/catch_test_macros.hpp>

#include <map>
#include <memory>

#include "test_support.hpp"

using namespace openback::app_auth;
using test_support::FakeTransport;
using test_support::json;
using test_support::json_response;
using test_support::kIssuer;
using test_support::TestKey;

namespace {

const std::string kWebClient = "uapp_web";
const std::string kSecret = "s3cr+t/x";  // url-encoded in the Basic header: s3cr%2Bt%2Fx
const std::string kRedirect = "https://app.example.com/callback";

struct WebFixture {
    TestKey key{"kid_w"};
    std::shared_ptr<FakeTransport> http = std::make_shared<FakeTransport>();

    WebFixture() {
        const json jwks = test_support::jwks_of({&key});
        http->on("GET", kIssuer + "/.well-known/jwks.json", [jwks](const HttpRequest&) { return json_response(200, jwks); });
    }

    OidcWebClient client(ClientAuthMethod method = ClientAuthMethod::ClientSecretBasic) const {
        OidcWebClientOptions options;
        options.client_secret = kSecret;
        options.redirect_uri = kRedirect;
        options.auth_method = method;
        options.http = http;
        return OidcWebClient(kIssuer, kWebClient, options);
    }

    void serve_tokens(const std::string& nonce) {
        const std::string id_token = test_support::make_id_token(key, nonce, kWebClient);
        const std::string access = test_support::make_access_token(key, json{{"aud", kWebClient}});
        http->on("POST", kIssuer + "/token", [id_token, access](const HttpRequest&) {
            return json_response(200, json{{"access_token", access},
                                           {"token_type", "Bearer"},
                                           {"expires_in", 900},
                                           {"scope", "openid profile email"},
                                           {"refresh_token", "obur_w1"},
                                           {"refresh_expires_in", 2592000},
                                           {"id_token", id_token}});
        });
    }
};

}  // namespace

TEST_CASE("web client: authorization URL and transaction", "[web]") {
    WebFixture f;
    const OidcWebClient oidc = f.client();
    AuthorizationOptions options;
    options.scope = "openid profile email offline_access";
    const AuthorizationRequest tx = oidc.authorization_url(options);
    const auto query = parse_query_string(tx.url.substr(tx.url.find('?') + 1));
    CHECK(query.at("client_id") == kWebClient);
    CHECK(query.at("redirect_uri") == kRedirect);
    CHECK(query.at("scope") == "openid profile email offline_access");
    CHECK(query.at("code_challenge") == code_challenge_s256(tx.code_verifier));
    CHECK(tx.redirect_uri == kRedirect);
    CHECK(oidc.logout_url().find(kIssuer + "/logout?client_id=uapp_web") == 0);
}

TEST_CASE("web client: callback with client_secret_basic and a verified ID token", "[web]") {
    WebFixture f;
    const OidcWebClient oidc = f.client();
    const AuthorizationRequest tx = oidc.authorization_url();
    f.serve_tokens(tx.nonce);

    const std::map<std::string, std::string> params = {{"code", "c0de"}, {"state", tx.state}, {"iss", kIssuer}};
    const CallbackResult result = oidc.handle_callback(params, tx);
    CHECK(result.tokens.refresh_token == "obur_w1");
    CHECK(result.tokens.expires_in == 900);
    CHECK(result.id_token_claims["sub"].get<std::string>() == "usr_1");

    const HttpRequest request = f.http->last("POST", kIssuer + "/token");
    CHECK(request.header("Authorization") == "Basic dWFwcF93ZWI6czNjciUyQnQlMkZ4");
    const auto form = parse_query_string(request.body);
    CHECK(form.at("grant_type") == "authorization_code");
    CHECK(form.at("code") == "c0de");
    CHECK(form.at("redirect_uri") == kRedirect);
    CHECK(code_challenge_s256(form.at("code_verifier")) ==
          parse_query_string(tx.url.substr(tx.url.find('?') + 1)).at("code_challenge"));
    CHECK(form.count("client_secret") == 0);

    // The transaction survives a round trip through the app's session store.
    const AuthorizationRequest restored = AuthorizationRequest::from_json(json::parse(tx.to_json().dump()));
    CHECK(oidc.handle_callback_url(kRedirect + "?code=c0de&state=" + tx.state, restored).tokens.refresh_token == "obur_w1");
}

TEST_CASE("web client: a wrong nonce or state is refused", "[web]") {
    WebFixture f;
    const OidcWebClient oidc = f.client();
    const AuthorizationRequest tx = oidc.authorization_url();
    f.serve_tokens("another-nonce");
    try {
        oidc.handle_callback({{"code", "c"}, {"state", tx.state}}, tx);
        FAIL("expected nonce_mismatch");
    } catch (const TokenVerificationError& e) {
        CHECK(e.reason() == "nonce_mismatch");
    }
    try {
        oidc.handle_callback({{"code", "c"}, {"state", "forged"}}, tx);
        FAIL("expected invalid_state");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "invalid_state");
    }
}

TEST_CASE("web client: client_secret_post, refresh, revoke, userinfo", "[web]") {
    WebFixture f;
    const OidcWebClient oidc = f.client(ClientAuthMethod::ClientSecretPost);
    f.serve_tokens("n");
    const TokenSet refreshed = oidc.refresh("obur_w0", std::string("org_2"));
    CHECK(refreshed.refresh_token == "obur_w1");
    HttpRequest request = f.http->last("POST", kIssuer + "/token");
    CHECK(request.header("Authorization").empty());
    auto form = parse_query_string(request.body);
    CHECK(form.at("grant_type") == "refresh_token");
    CHECK(form.at("refresh_token") == "obur_w0");
    CHECK(form.at("org_id") == "org_2");
    CHECK(form.at("client_id") == kWebClient);
    CHECK(form.at("client_secret") == kSecret);

    f.http->on("POST", kIssuer + "/revoke", [](const HttpRequest&) {
        HttpResponse r;
        r.status = 200;
        return r;
    });
    oidc.revoke("obur_w1");
    form = parse_query_string(f.http->last("POST", kIssuer + "/revoke").body);
    CHECK(form.at("token") == "obur_w1");

    f.http->on("GET", kIssuer + "/userinfo", [](const HttpRequest& r) {
        if (r.header("Authorization") != "Bearer good") return json_response(401, json{{"error", "invalid_token"}});
        return json_response(200, json{{"sub", "usr_1"}, {"email", "ada@example.com"}, {"org_id", nullptr}});
    });
    CHECK(oidc.userinfo("good")["sub"].get<std::string>() == "usr_1");
    try {
        oidc.userinfo("bad");
        FAIL("expected invalid_token");
    } catch (const AppAuthError& e) {
        CHECK(e.status() == 401);
        CHECK(e.code() == "invalid_token");
    }
}

TEST_CASE("web client: a token endpoint error is an AppAuthError with the OAuth code", "[web]") {
    WebFixture f;
    const OidcWebClient oidc = f.client();
    f.http->on("POST", kIssuer + "/token", [](const HttpRequest&) {
        return json_response(400, json{{"error", "invalid_grant"}, {"error_description", "code already used"}});
    });
    try {
        oidc.refresh("obur_used");
        FAIL("expected invalid_grant");
    } catch (const AppAuthError& e) {
        CHECK(e.status() == 400);
        CHECK(e.code() == "invalid_grant");
        CHECK(std::string(e.what()) == "code already used");
    }
}
