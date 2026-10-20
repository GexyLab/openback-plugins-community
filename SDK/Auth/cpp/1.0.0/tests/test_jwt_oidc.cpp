#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

#include "test_support.hpp"

using namespace openback::app_auth;
using test_support::json;
using test_support::kClientId;
using test_support::kIssuer;

TEST_CASE("base64url encodes and decodes every length", "[jwt]") {
    std::string bytes;
    for (int length = 0; length < 20; ++length) {
        const std::string encoded = base64url_encode(bytes);
        CHECK(encoded.find('=') == std::string::npos);
        CHECK(encoded.find('+') == std::string::npos);
        CHECK(encoded.find('/') == std::string::npos);
        CHECK(base64url_decode(encoded) == bytes);
        bytes.push_back(static_cast<char>(0xF0 + length));
    }
    CHECK(base64url_decode("aGVsbG8") == "hello");
    CHECK(base64url_encode("\xfb\xff") == "-_8");
    CHECK_THROWS_AS(base64url_decode("aGVs*G8"), std::invalid_argument);
    CHECK_THROWS_AS(base64url_decode("aGVsb"), std::invalid_argument);   // length % 4 == 1
    CHECK_THROWS_AS(base64url_decode("aGVsbG8="), std::invalid_argument);  // no padding in JWTs
}

TEST_CASE("decode_jwt_payload reads claims without verifying", "[jwt]") {
    const std::string token = base64url_encode(R"({"alg":"ES256"})") + "." + base64url_encode(R"({"sub":"usr_1"})") + ".sig";
    const auto claims = decode_jwt_payload(token);
    REQUIRE(claims);
    CHECK((*claims)["sub"].get<std::string>() == "usr_1");
    CHECK(decode_jwt_header(token).value()["alg"].get<std::string>() == "ES256");
    CHECK_FALSE(decode_jwt_payload("not-a-jwt"));
    CHECK_FALSE(decode_jwt_payload("a.b.c.d"));
}

TEST_CASE("PKCE S256 matches RFC 7636 appendix B", "[oidc]") {
    CHECK(code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") ==
          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    const std::string verifier = generate_code_verifier();
    CHECK(verifier.size() == 64);
    CHECK(verifier.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") ==
          std::string::npos);
    CHECK(generate_code_verifier() != verifier);
}

TEST_CASE("parse_query_string decodes and keeps the first occurrence", "[oidc]") {
    const auto params = parse_query_string("a=1+2&b=%2F%3D&a=3&empty=&flag");
    CHECK(params.at("a") == "1 2");
    CHECK(params.at("b") == "/=");
    CHECK(params.at("empty").empty());
    CHECK(params.at("flag").empty());
}

TEST_CASE("build_authorization_request sends PKCE S256, state, nonce and the extras", "[oidc]") {
    AuthorizationOptions options;
    options.provider = "uprov_google";
    options.org_id = "org_9";
    options.prompt = "login";
    options.screen_hint = "signup";
    options.login_hint = "ada@example.com";
    options.ui_locales = "it";
    options.max_age = 300;
    const AuthorizationRequest request =
        build_authorization_request(kIssuer + "/", kClientId, "com.example.app:/callback", options);
    const std::string prefix = kIssuer + "/authorize?";
    REQUIRE(request.url.compare(0, prefix.size(), prefix) == 0);
    const auto query = parse_query_string(request.url.substr(prefix.size()));
    CHECK(query.at("response_type") == "code");
    CHECK(query.at("client_id") == kClientId);
    CHECK(query.at("redirect_uri") == "com.example.app:/callback");
    CHECK(query.at("scope") == "openid profile email");
    CHECK(query.at("state") == request.state);
    CHECK(query.at("nonce") == request.nonce);
    CHECK(query.at("code_challenge_method") == "S256");
    CHECK(query.at("code_challenge") == code_challenge_s256(request.code_verifier));
    CHECK(query.at("provider") == "uprov_google");
    CHECK(query.at("org_id") == "org_9");
    CHECK(query.at("prompt") == "login");
    CHECK(query.at("screen_hint") == "signup");
    CHECK(query.at("login_hint") == "ada@example.com");
    CHECK(query.at("ui_locales") == "it");
    CHECK(query.at("max_age") == "300");
    CHECK(request.state.size() >= 22);
    CHECK(request.redirect_uri == "com.example.app:/callback");

    const AuthorizationRequest copy = AuthorizationRequest::from_json(request.to_json());
    CHECK(copy.state == request.state);
    CHECK(copy.code_verifier == request.code_verifier);

    CHECK_THROWS_AS(build_authorization_request(kIssuer, kClientId, ""), AppAuthError);
}

TEST_CASE("validate_callback checks error, code, state and iss", "[oidc]") {
    AuthorizationRequest tx;
    tx.state = "st_123";
    tx.redirect_uri = "com.example.app:/callback";

    const auto ok = CallbackParams::from_url("com.example.app:/callback?code=c0de&state=st_123&iss=" +
                                             std::string("https%3A%2F%2Fapi.example.com%2Fgateway%2Fshop%2Fauth%2Fmain"));
    CHECK(validate_callback(ok, tx, kIssuer) == "c0de");

    const auto wrong_state = CallbackParams::from_url("com.example.app:/callback?code=c0de&state=other");
    try {
        validate_callback(wrong_state, tx, kIssuer);
        FAIL("expected invalid_state");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "invalid_state");
        CHECK(e.status() == 400);
    }

    const auto wrong_iss = CallbackParams::from_url("x:/cb?code=c&state=st_123&iss=https%3A%2F%2Fevil.example");
    try {
        validate_callback(wrong_iss, tx, kIssuer);
        FAIL("expected invalid_issuer");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "invalid_issuer");
    }

    const auto error = CallbackParams::from_url("x:/cb?error=login_required&state=st_123");
    try {
        validate_callback(error, tx, kIssuer);
        FAIL("expected login_required");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "login_required");
    }

    const auto none = CallbackParams::from_url("x:/cb?state=st_123");
    CHECK_FALSE(none.is_callback());
    CHECK_THROWS_AS(validate_callback(none, tx, kIssuer), AppAuthError);

    const auto fragment = CallbackParams::from_url("x:/cb#code=f&state=st_123");
    CHECK(fragment.code.value() == "f");
    const auto bare = CallbackParams::from_url("code=b&state=st_123");
    CHECK(bare.code.value() == "b");
}

TEST_CASE("build_logout_url", "[oidc]") {
    LogoutOptions options;
    options.id_token_hint = "eyJ.x.y";
    options.post_logout_redirect_uri = "https://app.example.com/bye";
    options.state = "s1";
    const std::string url = build_logout_url(kIssuer, kClientId, options);
    const std::string prefix = kIssuer + "/logout?";
    REQUIRE(url.compare(0, prefix.size(), prefix) == 0);
    const auto query = parse_query_string(url.substr(prefix.size()));
    CHECK(query.at("client_id") == kClientId);
    CHECK(query.at("id_token_hint") == "eyJ.x.y");
    CHECK(query.at("post_logout_redirect_uri") == "https://app.example.com/bye");
    CHECK(query.at("state") == "s1");
}
