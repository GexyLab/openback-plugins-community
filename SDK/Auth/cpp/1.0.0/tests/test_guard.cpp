#include <catch2/catch_test_macros.hpp>

#include <memory>

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

struct GuardFixture {
    TestKey key{"kid_g"};
    std::shared_ptr<FakeTransport> http = std::make_shared<FakeTransport>();

    GuardFixture() {
        const json jwks = test_support::jwks_of({&key});
        http->on("GET", kIssuer + "/.well-known/jwks.json", [jwks](const HttpRequest&) { return json_response(200, jwks); });
    }

    BearerGuard guard(GuardOptions options = {}) const {
        VerifierOptions o;
        o.audiences = {kClientId};
        o.http = http;
        return BearerGuard(TokenVerifier(kIssuer, o), options);
    }
};

}  // namespace

TEST_CASE("extract_bearer_token", "[guard]") {
    CHECK(extract_bearer_token("Bearer abc").value() == "abc");
    CHECK(extract_bearer_token("  bearer   abc  ").value() == "abc");
    CHECK_FALSE(extract_bearer_token(""));
    CHECK_FALSE(extract_bearer_token("Basic dXNlcjpwYXNz"));
    CHECK_FALSE(extract_bearer_token("Bearer"));
    CHECK_FALSE(extract_bearer_token("Bearer a b"));
    CHECK_FALSE(extract_bearer_token("Bearerabc"));
}

TEST_CASE("a missing or invalid token answers 401 invalid_token", "[guard]") {
    GuardFixture f;
    const BearerGuard guard = f.guard();
    for (const std::string header : {std::string(), std::string("Basic eDp5"), std::string("Bearer not.a.jwt")}) {
        const GuardResult r = guard.check(header);
        CHECK_FALSE(r);
        CHECK(r.status == 401);
        CHECK(r.error == "invalid_token");
        CHECK(json::parse(r.body)["error"].get<std::string>() == "invalid_token");
        bool has_challenge = false;
        for (const auto& h : r.headers) {
            if (h.first == "WWW-Authenticate" && h.second == "Bearer error=\"invalid_token\"") has_challenge = true;
        }
        CHECK(has_challenge);
    }
}

TEST_CASE("a valid token passes with the user", "[guard]") {
    GuardFixture f;
    const GuardResult r = f.guard().check("Bearer " + make_access_token(f.key));
    REQUIRE(r);
    CHECK(r.status == 200);
    CHECK(r.user->id == "usr_1");
}

TEST_CASE("guests are refused unless allowed", "[guard]") {
    GuardFixture f;
    const std::string guest = "Bearer " + make_access_token(f.key, json{{"anon", true}, {"email", nullptr}});
    const GuardResult refused = f.guard().check(guest);
    CHECK(refused.status == 403);
    CHECK(json::parse(refused.body)["error"].get<std::string>() == "insufficient_scope");

    GuardOptions allow;
    allow.allow_anonymous = true;
    CHECK(f.guard(allow).check(guest));
}

TEST_CASE("roles (any of), permissions (all of), verified email", "[guard]") {
    GuardFixture f;
    const std::string member = "Bearer " + make_access_token(f.key);

    GuardOptions admins;
    admins.require_roles = {"admin", "owner"};
    CHECK(f.guard(admins).check(member).status == 403);
    const std::string admin = "Bearer " + make_access_token(f.key, json{{"roles", json::array({"owner"})}});
    CHECK(f.guard(admins).check(admin));

    GuardOptions perms;
    perms.require_permissions = {"orders.read", "orders.write"};
    CHECK(f.guard(perms).check(member).status == 403);
    const std::string star = "Bearer " + make_access_token(f.key, json{{"permissions", json::array({"*"})}});
    CHECK(f.guard(perms).check(star));

    GuardOptions verified;
    verified.require_verified_email = true;
    CHECK(f.guard(verified).check(member));
    const std::string unverified = "Bearer " + make_access_token(f.key, json{{"email_verified", false}});
    CHECK(f.guard(verified).check(unverified).status == 403);
}

TEST_CASE("keys unavailable answers 503", "[guard]") {
    GuardFixture f;
    f.http->on("GET", kIssuer + "/.well-known/jwks.json", [](const HttpRequest&) { return json_response(500, json::object()); });
    const GuardResult r = f.guard().check("Bearer " + make_access_token(f.key));
    CHECK(r.status == 503);
    CHECK(r.error == "temporarily_unavailable");
}
