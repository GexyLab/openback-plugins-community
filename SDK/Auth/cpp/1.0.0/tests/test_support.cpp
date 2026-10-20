#include "test_support.hpp"

#include <stdexcept>
#include <utility>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

namespace test_support {

using openback::app_auth::base64url_encode;

void FakeTransport::on(const std::string& method, const std::string& url_prefix, Handler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    routes_.emplace_back(method, url_prefix, std::move(handler));
}

HttpResponse FakeTransport::send(const HttpRequest& request) {
    Handler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        requests_.push_back(request);
        for (auto it = routes_.rbegin(); it != routes_.rend(); ++it) {
            const auto& [method, prefix, h] = *it;
            if (method == request.method && request.url.compare(0, prefix.size(), prefix) == 0) {
                handler = h;
                break;
            }
        }
    }
    if (!handler) return json_response(404, json{{"detail", "Not Found"}});
    return handler(request);  // outside the lock: handlers may block (single-flight tests)
}

std::vector<HttpRequest> FakeTransport::requests() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return requests_;
}

std::size_t FakeTransport::count(const std::string& method, const std::string& url_prefix) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t n = 0;
    for (const auto& r : requests_) {
        if (r.method == method && r.url.compare(0, url_prefix.size(), url_prefix) == 0) ++n;
    }
    return n;
}

HttpRequest FakeTransport::last(const std::string& method, const std::string& url_prefix) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = requests_.rbegin(); it != requests_.rend(); ++it) {
        if (it->method == method && it->url.compare(0, url_prefix.size(), url_prefix) == 0) return *it;
    }
    throw std::runtime_error("no request to " + method + " " + url_prefix);
}

HttpResponse json_response(int status, const json& body) {
    HttpResponse response;
    response.status = status;
    response.headers.emplace_back("Content-Type", "application/json");
    response.body = body.dump();
    return response;
}

TestKey::TestKey(std::string kid) : kid_(std::move(kid)) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    const bool ok = ctx != nullptr && EVP_PKEY_keygen_init(ctx) > 0 &&
                    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) > 0 &&
                    EVP_PKEY_keygen(ctx, &key_) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (!ok || key_ == nullptr) throw std::runtime_error("P-256 key generation failed");
    // SubjectPublicKeyInfo DER of a P-256 key ends with the uncompressed point 04 || X || Y (65 bytes).
    const int length = i2d_PUBKEY(key_, nullptr);
    if (length < 65) throw std::runtime_error("i2d_PUBKEY failed");
    std::vector<unsigned char> der(static_cast<std::size_t>(length));
    unsigned char* out = der.data();
    i2d_PUBKEY(key_, &out);
    const std::size_t point = der.size() - 65;
    if (der[point] != 0x04) throw std::runtime_error("unexpected public key encoding");
    x_.assign(reinterpret_cast<const char*>(der.data() + point + 1), 32);
    y_.assign(reinterpret_cast<const char*>(der.data() + point + 33), 32);
}

TestKey::~TestKey() { EVP_PKEY_free(key_); }

json TestKey::jwk() const {
    return json{{"kty", "EC"}, {"crv", "P-256"},  {"x", base64url_encode(x_)}, {"y", base64url_encode(y_)},
                {"kid", kid_}, {"alg", "ES256"}, {"use", "sig"}};
}

std::string TestKey::sign(const json& header, const json& claims) const {
    const std::string input = base64url_encode(header.dump()) + "." + base64url_encode(claims.dump());
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    std::size_t length = 0;
    if (md == nullptr || EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, key_) != 1 ||
        EVP_DigestSignUpdate(md, input.data(), input.size()) != 1 || EVP_DigestSignFinal(md, nullptr, &length) != 1) {
        EVP_MD_CTX_free(md);
        throw std::runtime_error("signing failed");
    }
    std::vector<unsigned char> der(length);
    if (EVP_DigestSignFinal(md, der.data(), &length) != 1) {
        EVP_MD_CTX_free(md);
        throw std::runtime_error("signing failed");
    }
    EVP_MD_CTX_free(md);
    const unsigned char* in = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &in, static_cast<long>(length));
    if (sig == nullptr) throw std::runtime_error("bad DER signature");
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    unsigned char raw[64];
    BN_bn2binpad(r, raw, 32);
    BN_bn2binpad(s, raw + 32, 32);
    ECDSA_SIG_free(sig);
    return input + "." + base64url_encode(std::string(reinterpret_cast<const char*>(raw), sizeof(raw)));
}

json jwks_of(std::initializer_list<const TestKey*> keys) {
    json list = json::array();
    for (const TestKey* key : keys) list.push_back(key->jwk());
    return json{{"keys", list}};
}

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string make_access_token(const TestKey& key, const json& extra, const std::string& typ,
                              const std::string& kid_override) {
    const std::int64_t now = now_seconds();
    json claims = {{"iss", kIssuer},
                   {"sub", "usr_1"},
                   {"aud", kClientId},
                   {"azp", kClientId},
                   {"exp", now + 900},
                   {"iat", now},
                   {"jti", "jti_1"},
                   {"sid", "ses_1"},
                   {"pool", "upool_1"},
                   {"sv", 1},
                   {"org_id", "org_1"},
                   {"roles", json::array({"member"})},
                   {"permissions", json::array({"orders.read"})},
                   {"email", "ada@example.com"},
                   {"email_verified", true},
                   {"amr", json::array({"pwd"})},
                   {"scope", "openid profile email"},
                   {"attr", json{{"plan", "pro"}}}};
    for (auto it = extra.begin(); it != extra.end(); ++it) {
        if (it.value().is_null()) {
            claims.erase(it.key());
        } else {
            claims[it.key()] = it.value();
        }
    }
    json header = {{"alg", "ES256"}, {"kid", kid_override.empty() ? key.kid() : kid_override}};
    if (!typ.empty()) header["typ"] = typ;
    return key.sign(header, claims);
}

std::string make_id_token(const TestKey& key, const std::string& nonce, const std::string& aud) {
    const std::int64_t now = now_seconds();
    const json claims = {{"iss", kIssuer},   {"sub", "usr_1"},    {"aud", aud},       {"azp", aud},
                         {"exp", now + 600}, {"iat", now},        {"auth_time", now}, {"nonce", nonce},
                         {"email", "ada@example.com"}, {"email_verified", true}};
    return key.sign(json{{"alg", "ES256"}, {"typ", "JWT"}, {"kid", key.kid()}}, claims);
}

}  // namespace test_support
