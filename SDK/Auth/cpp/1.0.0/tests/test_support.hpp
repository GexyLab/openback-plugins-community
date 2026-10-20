// Test helpers: a fake HTTP transport (no network) and an ES256 key pair generated with OpenSSL to sign test tokens.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <vector>

#include <openssl/evp.h>

#include <openback/app_auth.hpp>

namespace test_support {

using json = nlohmann::json;
using openback::app_auth::HttpRequest;
using openback::app_auth::HttpResponse;
using openback::app_auth::HttpTransport;

inline const std::string kIssuer = "https://api.example.com/gateway/shop/auth/main";
inline const std::string kClientId = "uapp_test";

/// Answers requests from registered routes ("METHOD", URL prefix); records every request. Unknown routes: 404.
class FakeTransport : public HttpTransport {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    /// The most recently registered matching route wins (a test can override a default route).
    void on(const std::string& method, const std::string& url_prefix, Handler handler);
    HttpResponse send(const HttpRequest& request) override;

    std::vector<HttpRequest> requests() const;
    std::size_t count(const std::string& method, const std::string& url_prefix) const;
    /// The last request to a route (throws std::runtime_error when there is none).
    HttpRequest last(const std::string& method, const std::string& url_prefix) const;

private:
    mutable std::mutex mutex_;
    std::vector<std::tuple<std::string, std::string, Handler>> routes_;
    std::vector<HttpRequest> requests_;
};

HttpResponse json_response(int status, const json& body);

/// A P-256 key pair.
class TestKey {
public:
    explicit TestKey(std::string kid);
    ~TestKey();
    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;

    const std::string& kid() const noexcept { return kid_; }
    /// The public JWK (kty EC, crv P-256, x, y, kid, alg ES256, use sig).
    json jwk() const;
    /// A compact JWS (ES256, JOSE R||S signature) of header.claims.
    std::string sign(const json& header, const json& claims) const;

private:
    EVP_PKEY* key_ = nullptr;
    std::string kid_;
    std::string x_;
    std::string y_;
};

json jwks_of(std::initializer_list<const TestKey*> keys);

std::int64_t now_seconds();

/// A pool-like access token: header {alg ES256, typ, kid}; `extra` claims are merged in (null removes a claim).
std::string make_access_token(const TestKey& key, const json& extra = json::object(), const std::string& typ = "at+jwt",
                              const std::string& kid_override = std::string());

/// An ID token (typ JWT) with a nonce.
std::string make_id_token(const TestKey& key, const std::string& nonce, const std::string& aud = kClientId);

/// A controllable clock for ClockFn options.
struct TestClock {
    std::shared_ptr<std::chrono::system_clock::time_point> now =
        std::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());

    openback::app_auth::ClockFn fn() const {
        auto shared = now;
        return [shared] { return *shared; };
    }
    void advance(std::chrono::seconds by) { *now += by; }
};

}  // namespace test_support
