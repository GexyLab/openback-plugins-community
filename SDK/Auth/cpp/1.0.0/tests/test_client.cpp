#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

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

const std::string kApi = kIssuer + "/api/v1";
const std::string kStorageKey = "openback.auth." + kClientId;

json user_json(const std::string& id = "usr_1") {
    return json{{"id", id},
                {"email", "ada@example.com"},
                {"email_verified", true},
                {"display_name", "Ada"},
                {"photo_url", nullptr},
                {"locale", "en"},
                {"attributes", json::object()},
                {"anonymous", false},
                {"created_at", "2026-10-01T10:00:00Z"},
                {"last_login_at", nullptr},
                {"mfa", json{{"totp", true}}}};
}

json ok_outcome(const std::string& access_token, const std::string& refresh_token, int expires_in = 900) {
    return json{{"status", "ok"},
                {"access_token", access_token},
                {"refresh_token", refresh_token},
                {"expires_in", expires_in},
                {"user", user_json()},
                {"org", nullptr}};
}

json tokens(const std::string& access_token, const std::string& refresh_token, int expires_in = 900) {
    return json{{"access_token", access_token},
                {"token_type", "Bearer"},
                {"expires_in", expires_in},
                {"scope", "openid profile email"},
                {"refresh_token", refresh_token},
                {"refresh_expires_in", 2592000}};
}

struct ClientFixture {
    TestKey key{"kid_c"};
    std::shared_ptr<FakeTransport> http = std::make_shared<FakeTransport>();
    std::shared_ptr<MemoryTokenStorage> storage = std::make_shared<MemoryTokenStorage>();
    std::string access_1 = make_access_token(key, json{{"jti", "a1"}});
    std::string access_2 = make_access_token(key, json{{"jti", "a2"}});

    ClientOptions options() const {
        ClientOptions o;
        o.http = http;
        o.storage = storage;
        o.redirect_uri = "com.example.app:/callback";
        return o;
    }

    // Signs in with a password; the access token expires in `expires_in` seconds.
    void sign_in(Client& client, int expires_in = 900) {
        const std::string access = access_1;
        http->on("POST", kApi + "/signin/password",
                 [access, expires_in](const HttpRequest&) { return json_response(200, ok_outcome(access, "obur_1", expires_in)); });
        REQUIRE(client.sign_in_with_password("ada@example.com", "correct horse").ok());
    }
};

std::string stored_refresh_token(MemoryTokenStorage& storage) {
    const auto text = storage.get(kStorageKey);
    if (!text) return {};
    return json::parse(*text)["refreshToken"].get<std::string>();
}

std::string header_of(const HttpRequest& request, const std::string& name) { return request.header(name); }

}  // namespace

TEST_CASE("sign in with a password keeps the session", "[client]") {
    ClientFixture f;
    Client client(kIssuer + "/", kClientId, f.options());
    CHECK(client.issuer() == kIssuer);
    CHECK_FALSE(client.is_signed_in());
    f.sign_in(client);

    CHECK(client.is_signed_in());
    REQUIRE(client.current_user());
    CHECK(client.current_user()->email.value() == "ada@example.com");
    CHECK(client.current_user()->mfa_totp);
    CHECK_FALSE(client.current_org());
    CHECK(client.access_token_claims().value()["jti"].get<std::string>() == "a1");
    CHECK(client.get_access_token() == f.access_1);

    const HttpRequest request = f.http->last("POST", kApi + "/signin/password");
    CHECK(header_of(request, "X-Client-Id") == kClientId);
    CHECK(header_of(request, "Content-Type") == "application/json");
    CHECK(header_of(request, "Accept") == "application/json");
    CHECK(header_of(request, "Authorization").empty());
    CHECK(header_of(request, "Origin").empty());
    const json body = json::parse(request.body);
    CHECK(body["email"].get<std::string>() == "ada@example.com");
    CHECK(body["password"].get<std::string>() == "correct horse");
    CHECK_FALSE(body.contains("org_id"));

    // Stored as {accessToken, refreshToken, idToken, expiresAt, user, org} under openback.auth.<client id>.
    const json stored = json::parse(f.storage->get(kStorageKey).value());
    CHECK(stored["refreshToken"].get<std::string>() == "obur_1");
    CHECK(stored["accessToken"].get<std::string>() == f.access_1);
    CHECK(stored["expiresAt"].get<std::int64_t>() > test_support::now_seconds() * 1000);
    CHECK(stored["user"]["id"].get<std::string>() == "usr_1");
    CHECK(stored["org"].is_null());

    // A new Client on the same storage restores the session.
    Client again(kIssuer, kClientId, f.options());
    CHECK(again.is_signed_in());
    CHECK(again.current_user()->id == "usr_1");
}

TEST_CASE("the MFA branch returns the token and keeps no session until verify_mfa", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.http->on("POST", kApi + "/signin/password",
               [](const HttpRequest&) { return json_response(200, json{{"status", "mfa_required"}, {"mfa_token", "mfa_1"}}); });
    const std::string access = f.access_1;
    f.http->on("POST", kApi + "/signin/mfa",
               [access](const HttpRequest&) { return json_response(200, ok_outcome(access, "obur_1")); });

    const Outcome first = client.sign_in_with_password("ada@example.com", "pw");
    CHECK(first.status == OutcomeStatus::MfaRequired);
    CHECK(first.mfa_token.value() == "mfa_1");
    CHECK_FALSE(client.is_signed_in());

    const Outcome second = client.verify_mfa(*first.mfa_token, "123456");
    CHECK(second.ok());
    CHECK(client.is_signed_in());
    CHECK_FALSE(second.raw.contains("access_token"));
    CHECK_FALSE(second.raw.contains("refresh_token"));
    const json body = json::parse(f.http->last("POST", kApi + "/signin/mfa").body);
    CHECK(body["mfa_token"].get<std::string>() == "mfa_1");
    CHECK(body["code"].get<std::string>() == "123456");
}

TEST_CASE("the other outcomes are returned typed", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.http->on("POST", kApi + "/signup",
               [](const HttpRequest&) { return json_response(200, json{{"status", "verification_required"}}); });
    f.http->on("POST", kApi + "/signin/email-code/verify", [](const HttpRequest&) {
        return json_response(200, json{{"status", "password_change_required"}, {"change_token", "chg_1"}});
    });
    f.http->on("POST", kApi + "/signin/anonymous",
               [](const HttpRequest&) { return json_response(200, json{{"status", "mfa_enroll_required"}, {"mfa_token", "m"}}); });

    SignUpParams params;
    params.email = "new@example.com";
    params.password = "long enough password";
    params.display_name = "New";
    params.locale = "it";
    CHECK(client.sign_up(params).status == OutcomeStatus::VerificationRequired);
    const json signup = json::parse(f.http->last("POST", kApi + "/signup").body);
    CHECK(signup["locale"].get<std::string>() == "it");
    CHECK(signup["display_name"].get<std::string>() == "New");

    EmailCodeParams code;
    code.email = "ada@example.com";
    code.code = "123456";
    const Outcome changed = client.sign_in_with_email_code(code);
    CHECK(changed.status == OutcomeStatus::PasswordChangeRequired);
    CHECK(changed.change_token.value() == "chg_1");

    const Outcome guest = client.sign_in_anonymously();
    CHECK(guest.status == OutcomeStatus::MfaEnrollRequired);
    CHECK(f.http->last("POST", kApi + "/signin/anonymous").body.empty());
    CHECK_FALSE(client.is_signed_in());
}

TEST_CASE("errors are mapped to AppAuthError", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());

    f.http->on("POST", kApi + "/signin/password", [](const HttpRequest&) {
        return json_response(401, json{{"detail", {{"code", "invalid_credentials"}, {"message", "Wrong email or password"}}}});
    });
    try {
        client.sign_in_with_password("ada@example.com", "wrong");
        FAIL("expected invalid_credentials");
    } catch (const AppAuthError& e) {
        CHECK(e.status() == 401);
        CHECK(e.code() == "invalid_credentials");
        CHECK(std::string(e.what()) == "Wrong email or password");
    }

    f.http->on("POST", kApi + "/signup", [](const HttpRequest&) {
        return json_response(422, json{{"detail", {{"code", "weak_password"}, {"message", "Weak"}, {"problems", json::array({"min_length"})}}}});
    });
    try {
        client.sign_up(SignUpParams{"a@example.com", "x", "", std::nullopt, std::nullopt});
        FAIL("expected weak_password");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "weak_password");
        CHECK(e.detail()["problems"][0].get<std::string>() == "min_length");
    }

    f.http->on("POST", kApi + "/password/forgot", [](const HttpRequest&) {
        return json_response(422, json{{"detail", json::array({json{{"loc", json::array({"body", "email"})}, {"msg", "field required"}}})}});
    });
    try {
        client.send_password_reset("");
        FAIL("expected a validation error");
    } catch (const AppAuthError& e) {
        CHECK(e.status() == 422);
        CHECK(std::string(e.what()) == "field required");
    }

    f.http->on("GET", kApi + "/config", [](const HttpRequest&) {
        HttpResponse r;
        r.status = 502;
        r.body = "<html>Bad gateway</html>";
        return r;
    });
    try {
        client.config();
        FAIL("expected http_502");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "http_502");
    }

    f.http->on("GET", kApi + "/config", [](const HttpRequest&) -> HttpResponse { throw std::runtime_error("timeout"); });
    try {
        client.config();
        FAIL("expected a network error");
    } catch (const AppAuthError& e) {
        CHECK(e.is_network_error());
        CHECK(e.code() == "network_error");
    }
}

TEST_CASE("get_access_token renews the token one minute before it expires and stores the rotated one", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client, 30);  // expires in 30 s: inside the 60 s window
    const std::string access = f.access_2;
    f.http->on("POST", kApi + "/token/refresh",
               [access](const HttpRequest&) { return json_response(200, tokens(access, "obur_2")); });

    CHECK(client.get_access_token() == f.access_2);
    CHECK(f.http->count("POST", kApi + "/token/refresh") == 1);
    const json body = json::parse(f.http->last("POST", kApi + "/token/refresh").body);
    CHECK(body["refresh_token"].get<std::string>() == "obur_1");
    CHECK(stored_refresh_token(*f.storage) == "obur_2");
    CHECK(client.current_user()->id == "usr_1");  // the user is kept across a refresh

    // Fresh now: no new request.
    CHECK(client.get_access_token() == f.access_2);
    CHECK(f.http->count("POST", kApi + "/token/refresh") == 1);
}

TEST_CASE("concurrent callers share one refresh (single-flight)", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client, 10);
    std::atomic<int> calls{0};
    const std::string access = f.access_2;
    f.http->on("POST", kApi + "/token/refresh", [&calls, access](const HttpRequest&) {
        ++calls;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        return json_response(200, tokens(access, "obur_2"));
    });

    std::vector<std::thread> threads;
    std::vector<std::string> results(8);
    for (std::size_t i = 0; i < results.size(); ++i) {
        threads.emplace_back([&client, &results, i] { results[i] = client.get_access_token(); });
    }
    for (auto& t : threads) t.join();
    CHECK(calls.load() == 1);
    for (const auto& token : results) CHECK(token == f.access_2);
    CHECK(stored_refresh_token(*f.storage) == "obur_2");
}

TEST_CASE("a refused refresh token ends the session and tells the listeners", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    std::vector<bool> seen;
    auto unsubscribe = client.on_auth_state_changed(
        [&seen](const std::optional<PoolUser>& user, const std::optional<ActiveOrg>&) { seen.push_back(user.has_value()); });
    REQUIRE(seen == std::vector<bool>{false});  // called at once

    f.sign_in(client, 10);
    CHECK(seen.back());
    f.http->on("POST", kApi + "/token/refresh", [](const HttpRequest&) {
        return json_response(401, json{{"detail", {{"code", "invalid_refresh_token"}, {"message", "Session expired"}}}});
    });
    try {
        client.get_access_token();
        FAIL("expected invalid_refresh_token");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "invalid_refresh_token");
    }
    CHECK_FALSE(client.is_signed_in());
    CHECK_FALSE(seen.back());
    CHECK_FALSE(f.storage->get(kStorageKey));

    unsubscribe();
    const std::size_t before = seen.size();
    f.sign_in(client);
    CHECK(seen.size() == before);
}

TEST_CASE("a network error during a refresh is surfaced, not retried, and keeps the session", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client, 10);
    f.http->on("POST", kApi + "/token/refresh", [](const HttpRequest&) -> HttpResponse { throw std::runtime_error("reset"); });
    CHECK_THROWS_AS(client.get_access_token(), AppAuthError);
    CHECK(f.http->count("POST", kApi + "/token/refresh") == 1);
    CHECK(client.is_signed_in());
    CHECK(stored_refresh_token(*f.storage) == "obur_1");
}

TEST_CASE("a 401 token_* on a signed-in call clears the session", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client);
    f.http->on("GET", kApi + "/me", [](const HttpRequest&) {
        return json_response(401, json{{"detail", {{"code", "token_revoked"}, {"message", "Signed out"}}}});
    });
    CHECK_THROWS_AS(client.me(), AppAuthError);
    CHECK_FALSE(client.is_signed_in());
}

TEST_CASE("signed-in calls send the bearer token", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client);
    json updated = user_json();
    updated["display_name"] = "Ada L.";
    f.http->on("PATCH", kApi + "/me", [updated](const HttpRequest&) { return json_response(200, updated); });
    f.http->on("GET", kApi + "/orgs/org%201/members", [](const HttpRequest&) {
        return json_response(200, json{{"items", json::array({json{{"user_id", "usr_2"}, {"email", "b@example.com"}, {"display_name", "B"},
                                                                   {"disabled", false}, {"roles", json::array({"admin"})},
                                                                   {"created_at", "2026-10-01"}}})},
                                       {"total", 1},
                                       {"roles", json::array({json{{"key", "admin"}, {"label", "Admin"}}})}});
    });
    f.http->on("GET", "https://api.example.com/orders", [](const HttpRequest&) { return json_response(200, json::array()); });

    ProfileUpdate update;
    update.display_name = "Ada L.";
    CHECK(client.update_profile(update).display_name == "Ada L.");
    CHECK(client.current_user()->display_name == "Ada L.");
    const HttpRequest patch = f.http->last("PATCH", kApi + "/me");
    CHECK(header_of(patch, "Authorization") == "Bearer " + f.access_1);
    CHECK(json::parse(patch.body).size() == 1);

    MemberQuery query;
    query.q = "b@";
    query.limit = 10;
    const MemberPage page = client.members("org 1", query);
    REQUIRE(page.items.size() == 1);
    CHECK(page.items[0].roles == std::vector<std::string>{"admin"});
    CHECK(page.total.value() == 1);
    CHECK(page.roles.at(0).label == "Admin");
    CHECK(f.http->last("GET", kApi + "/orgs/").url == kApi + "/orgs/org%201/members?q=b%40&skip=0&limit=10");

    HttpRequest own;
    own.url = "https://api.example.com/orders";
    own.set_header("authorization", "Bearer stale");
    CHECK(client.authorized_request(own).status == 200);
    CHECK(header_of(f.http->last("GET", "https://api.example.com/orders"), "Authorization") == "Bearer " + f.access_1);
}

TEST_CASE("switch_organization uses the refresh token under the single-flight lock", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client);
    const std::string access = f.access_2;
    f.http->on("POST", kApi + "/orgs/switch", [access](const HttpRequest&) {
        json out = tokens(access, "obur_2");
        out["org"] = json{{"id", "org_2"}, {"name", "Two"}, {"roles", json::array({"owner"})}, {"choices", 2}};
        return json_response(200, out);
    });
    const auto org = client.switch_organization("org_2");
    REQUIRE(org);
    CHECK(org->id == "org_2");
    CHECK(org->choices == 2);
    const HttpRequest request = f.http->last("POST", kApi + "/orgs/switch");
    const json body = json::parse(request.body);
    CHECK(body["org_id"].get<std::string>() == "org_2");
    CHECK(body["refresh_token"].get<std::string>() == "obur_1");
    CHECK(header_of(request, "Authorization") == "Bearer " + f.access_1);
    CHECK(stored_refresh_token(*f.storage) == "obur_2");
    CHECK(client.get_access_token() == f.access_2);
}

TEST_CASE("sign_out always clears locally, change_password and delete_account too", "[client]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    f.sign_in(client);
    f.http->on("POST", kApi + "/signout", [](const HttpRequest&) { return json_response(500, json::object()); });
    client.sign_out(true);
    CHECK_FALSE(client.is_signed_in());
    const json body = json::parse(f.http->last("POST", kApi + "/signout").body);
    CHECK(body["refresh_token"].get<std::string>() == "obur_1");
    CHECK(body["everywhere"].get<bool>());

    f.sign_in(client);
    f.http->on("POST", kApi + "/me/password", [](const HttpRequest&) { return json_response(200, json{{"status", "password_changed"}}); });
    client.change_password(std::string("old"), "new long password");
    CHECK_FALSE(client.is_signed_in());

    f.sign_in(client);
    f.http->on("DELETE", kApi + "/me", [](const HttpRequest&) { return json_response(200, json{{"status", "deleted"}}); });
    client.delete_account(std::string("pw"));
    CHECK_FALSE(client.is_signed_in());
    CHECK(json::parse(f.http->last("DELETE", kApi + "/me").body)["password"].get<std::string>() == "pw");
}

TEST_CASE("hosted sign-in: authorization request, callback, code exchange with PKCE", "[client][oidc]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    const AuthorizationRequest request = client.build_authorization_request();
    CHECK(f.storage->get(kStorageKey + ".pkce"));
    const auto query = parse_query_string(request.url.substr(request.url.find('?') + 1));
    const std::string challenge = query.at("code_challenge");

    const std::string id_token = test_support::make_id_token(f.key, request.nonce);
    const std::string access = f.access_1;
    f.http->on("POST", kIssuer + "/token", [challenge, id_token, access](const HttpRequest& r) {
        const auto form = parse_query_string(r.body);
        if (form.at("grant_type") != "authorization_code" || form.at("code") != "c0de" ||
            form.at("client_id") != kClientId || form.at("redirect_uri") != "com.example.app:/callback" ||
            code_challenge_s256(form.at("code_verifier")) != challenge || r.header("Content-Type") != "application/x-www-form-urlencoded") {
            return json_response(400, json{{"error", "invalid_grant"}, {"error_description", "PKCE verification failed"}});
        }
        json out = tokens(access, "obur_9");
        out["id_token"] = id_token;
        return json_response(200, out);
    });
    f.http->on("GET", kApi + "/me", [](const HttpRequest&) { return json_response(200, user_json()); });

    // A forged state is refused and the transaction stays for the real callback.
    CHECK_THROWS_AS(client.handle_redirect_callback("com.example.app:/callback?code=c0de&state=forged"), AppAuthError);
    CHECK(f.storage->get(kStorageKey + ".pkce"));

    const auto user = client.handle_redirect_callback("com.example.app:/callback?code=c0de&state=" + request.state +
                                                      "&iss=https%3A%2F%2Fapi.example.com%2Fgateway%2Fshop%2Fauth%2Fmain");
    REQUIRE(user);
    CHECK(user->id == "usr_1");
    CHECK(client.is_signed_in());
    CHECK_FALSE(f.storage->get(kStorageKey + ".pkce"));
    CHECK(stored_refresh_token(*f.storage) == "obur_9");

    const std::string logout = client.build_logout_url(std::string("com.example.app:/signed-out"));
    const auto logout_query = parse_query_string(logout.substr(logout.find('?') + 1));
    CHECK(logout_query.at("id_token_hint") == id_token);
    CHECK(logout_query.at("client_id") == kClientId);
}

TEST_CASE("hosted sign-in: a wrong nonce or an error redirect is refused", "[client][oidc]") {
    ClientFixture f;
    Client client(kIssuer, kClientId, f.options());
    AuthorizationRequest request = client.build_authorization_request();
    const std::string bad_id_token = test_support::make_id_token(f.key, "not-the-nonce");
    const std::string access = f.access_1;
    f.http->on("POST", kIssuer + "/token", [bad_id_token, access](const HttpRequest&) {
        json out = tokens(access, "obur_9");
        out["id_token"] = bad_id_token;
        return json_response(200, out);
    });
    try {
        client.handle_redirect_callback("com.example.app:/callback?code=c&state=" + request.state);
        FAIL("expected invalid_nonce");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "invalid_nonce");
    }
    CHECK_FALSE(client.is_signed_in());

    request = client.build_authorization_request();
    try {
        client.handle_redirect_callback("com.example.app:/callback?error=access_denied&error_description=Denied&state=" +
                                        request.state);
        FAIL("expected access_denied");
    } catch (const AppAuthError& e) {
        CHECK(e.code() == "access_denied");
        CHECK(std::string(e.what()) == "Denied");
    }
    CHECK_THROWS_AS(client.handle_redirect_callback("com.example.app:/callback"), AppAuthError);
}
