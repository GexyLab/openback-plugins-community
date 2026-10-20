#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <memory>
#include <stdexcept>

#include "test_support.hpp"

using namespace openback::app_auth;
using test_support::FakeTransport;
using test_support::json;
using test_support::json_response;
using test_support::kClientId;
using test_support::kIssuer;
using test_support::make_access_token;
using test_support::TestKey;

namespace {

const std::string kJwksUrl = kIssuer + "/.well-known/jwks.json";

struct Fixture {
    TestKey key{"kid_a"};
    std::shared_ptr<FakeTransport> http = std::make_shared<FakeTransport>();
    test_support::TestClock clock;
    std::shared_ptr<json> jwks = std::make_shared<json>(test_support::jwks_of({&key}));

    Fixture() {
        auto served = jwks;
        http->on("GET", kJwksUrl, [served](const HttpRequest&) { return json_response(200, *served); });
    }

    VerifierOptions options() const {
        VerifierOptions o;
        o.audiences = {kClientId};
        o.http = http;
        o.clock = clock.fn();
        return o;
    }

    TokenVerifier verifier() const { return TokenVerifier(kIssuer, options()); }
};

std::string reason_of(const TokenVerifier& verifier, const std::string& token) {
    try {
        verifier.verify(token);
    } catch (const TokenVerificationError& e) {
        CHECK(e.status() == 401);
        CHECK(e.code() == "invalid_token");
        return e.reason();
    }
    return "accepted";
}

std::string forge(const json& header, const json& claims, const std::string& signature = "c2lnbmF0dXJl") {
    return base64url_encode(header.dump()) + "." + base64url_encode(claims.dump()) + "." + signature;
}

}  // namespace

TEST_CASE("a valid access token gives the AppUser", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    const AppUser user = verifier.verify(make_access_token(f.key));
    CHECK(user.id == "usr_1");
    CHECK(user.pool_id == "upool_1");
    CHECK(user.client_id == kClientId);
    CHECK(user.email.value() == "ada@example.com");
    CHECK(user.email_verified);
    CHECK_FALSE(user.anonymous);
    CHECK(user.org_id.value() == "org_1");
    CHECK(user.session_id.value() == "ses_1");
    CHECK(user.has_role("member"));
    CHECK_FALSE(user.has_role("admin"));
    CHECK(user.has_permission("orders.read"));
    CHECK_FALSE(user.has_permission("orders.write"));
    CHECK(user.amr == std::vector<std::string>{"pwd"});
    CHECK(user.attributes["plan"].get<std::string>() == "pro");
    CHECK(user.claims["jti"].get<std::string>() == "jti_1");

    // The keys are cached: a second token needs no request.
    verifier.verify(make_access_token(f.key));
    CHECK(f.http->count("GET", kJwksUrl) == 1);
}

TEST_CASE("permission \"*\" grants every permission", "[verifier]") {
    Fixture f;
    const AppUser user = f.verifier().verify(make_access_token(f.key, json{{"permissions", json::array({"*"})}}));
    CHECK(user.has_permission("anything.at.all"));
}

TEST_CASE("typ must be at+jwt for access tokens", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    CHECK(reason_of(verifier, make_access_token(f.key, json::object(), "application/at+jwt")) == "accepted");
    CHECK(reason_of(verifier, make_access_token(f.key, json::object(), "AT+JWT")) == "accepted");
    CHECK(reason_of(verifier, make_access_token(f.key, json::object(), "JWT")) == "wrong_type");
    CHECK(reason_of(verifier, make_access_token(f.key, json::object(), "")) == "wrong_type");
}

TEST_CASE("only ES256 is accepted (algorithm confusion)", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    const json claims = {{"iss", kIssuer}, {"sub", "usr_1"}, {"aud", kClientId}, {"exp", test_support::now_seconds() + 600}};
    CHECK(reason_of(verifier, forge({{"alg", "none"}, {"typ", "at+jwt"}, {"kid", "kid_a"}}, claims)) == "unsupported_alg");
    CHECK(reason_of(verifier, forge({{"alg", "HS256"}, {"typ", "at+jwt"}, {"kid", "kid_a"}}, claims)) == "unsupported_alg");
    CHECK(reason_of(verifier, forge({{"alg", "RS256"}, {"typ", "at+jwt"}, {"kid", "kid_a"}}, claims)) == "unsupported_alg");
    CHECK(reason_of(verifier, forge({{"alg", "none"}, {"typ", "at+jwt"}}, claims, "")) == "malformed");
    CHECK(reason_of(verifier, "a.b") == "malformed");
    CHECK(reason_of(verifier, "") == "malformed");
}

TEST_CASE("signatures are checked", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    const std::string token = make_access_token(f.key);

    // Claims changed after signing.
    const auto dot1 = token.find('.');
    const auto dot2 = token.find('.', dot1 + 1);
    const json other = {{"iss", kIssuer}, {"sub", "usr_admin"}, {"aud", kClientId},
                        {"exp", test_support::now_seconds() + 600}};
    const std::string tampered = token.substr(0, dot1 + 1) + base64url_encode(other.dump()) + token.substr(dot2);
    CHECK(reason_of(verifier, tampered) == "bad_signature");

    // Signed by another key that claims the same kid.
    TestKey intruder("kid_a");
    CHECK(reason_of(verifier, make_access_token(intruder)) == "bad_signature");

    // A signature of the wrong size.
    CHECK(reason_of(verifier, token.substr(0, dot2 + 1) + "AAAA") == "bad_signature");
}

TEST_CASE("iss, aud, exp, nbf and iat are checked with leeway", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    const std::int64_t now = test_support::now_seconds();
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"iss", "https://evil.example"}})) == "wrong_issuer");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"aud", "uapp_other"}})) == "wrong_audience");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"aud", json::array({"uapp_other", kClientId})}})) ==
          "accepted");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"exp", now - 120}})) == "expired");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"exp", now - 30}})) == "accepted");  // within 60 s
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"exp", nullptr}})) == "malformed");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"exp", "soon"}})) == "malformed");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"nbf", now + 300}})) == "not_yet_valid");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"nbf", now + 30}})) == "accepted");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"iat", now + 300}})) == "issued_in_future");
    CHECK(reason_of(verifier, make_access_token(f.key, json{{"sub", ""}})) == "missing_subject");
}

TEST_CASE("an unknown kid refetches the keys at most once per interval", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    TestKey rotated("kid_b");

    CHECK(reason_of(verifier, make_access_token(f.key)) == "accepted");
    CHECK(f.http->count("GET", kJwksUrl) == 1);

    // kid_b is unknown and the last fetch was just now: no new request.
    CHECK(reason_of(verifier, make_access_token(rotated)) == "unknown_key");
    CHECK(f.http->count("GET", kJwksUrl) == 1);

    // The pool rotated its key; 31 seconds later the unknown kid fetches the keys again.
    *f.jwks = test_support::jwks_of({&f.key, &rotated});
    f.clock.advance(std::chrono::seconds(31));
    CHECK(reason_of(verifier, make_access_token(rotated)) == "accepted");
    CHECK(f.http->count("GET", kJwksUrl) == 2);

    // Unknown kid again, right away: refused without a request.
    CHECK(reason_of(verifier, make_access_token(f.key, json::object(), "at+jwt", "kid_zzz")) == "unknown_key");
    CHECK(f.http->count("GET", kJwksUrl) == 2);
}

TEST_CASE("the key cache expires after jwks_cache_ttl", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    verifier.verify(make_access_token(f.key));
    f.clock.advance(std::chrono::seconds(601));
    verifier.verify(make_access_token(f.key));
    CHECK(f.http->count("GET", kJwksUrl) == 2);
}

TEST_CASE("keys that are not EC P-256 points on the curve are ignored", "[verifier]") {
    Fixture f;
    json bad = f.key.jwk();
    std::string y = base64url_decode(bad["y"].get<std::string>());
    y[31] = static_cast<char>(y[31] ^ 0x01);  // no longer on the curve
    bad["y"] = base64url_encode(y);
    *f.jwks = json{{"keys", json::array({bad, json{{"kty", "RSA"}, {"kid", "kid_rsa"}, {"n", "AQAB"}, {"e", "AQAB"}}})}};
    CHECK(reason_of(f.verifier(), make_access_token(f.key)) == "unknown_key");
}

TEST_CASE("an unreachable JWKS is a 503, not an invalid token", "[verifier]") {
    Fixture f;
    f.http->on("GET", kJwksUrl, [](const HttpRequest&) -> HttpResponse { throw std::runtime_error("connection refused"); });
    try {
        f.verifier().verify(make_access_token(f.key));
        FAIL("expected jwks_unavailable");
    } catch (const TokenVerificationError&) {
        FAIL("must not be an invalid token");
    } catch (const AppAuthError& e) {
        CHECK(e.status() == 503);
        CHECK(e.code() == "jwks_unavailable");
    }
}

TEST_CASE("set_jwks preloads the keys", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    verifier.set_jwks(test_support::jwks_of({&f.key}));
    CHECK(reason_of(verifier, make_access_token(f.key)) == "accepted");
    CHECK(f.http->count("GET", kJwksUrl) == 0);
}

TEST_CASE("ID tokens: typ JWT, audience and nonce", "[verifier]") {
    Fixture f;
    const TokenVerifier verifier = f.verifier();
    const std::string id_token = test_support::make_id_token(f.key, "n0nce");
    const json claims = verifier.verify_id_token(id_token, std::string("n0nce"));
    CHECK(claims["sub"].get<std::string>() == "usr_1");
    CHECK_THROWS_AS(verifier.verify_id_token(id_token, std::string("other")), TokenVerificationError);
    CHECK_THROWS_AS(verifier.verify(id_token), TokenVerificationError);  // not an access token
    CHECK_THROWS_AS(verifier.verify_id_token(test_support::make_id_token(f.key, "n0nce", "uapp_other")),
                    TokenVerificationError);
}

TEST_CASE("a verifier needs an audience", "[verifier]") {
    VerifierOptions options;
    options.http = std::make_shared<FakeTransport>();
    CHECK_THROWS_AS(TokenVerifier(kIssuer, options), std::invalid_argument);
}
