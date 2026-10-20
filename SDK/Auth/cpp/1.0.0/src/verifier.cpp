// openback-app-auth-cpp -- TokenVerifier: ES256 JWT verification with OpenSSL (3.x EVP; 1.1.1 fallback), JWKS cache.
#include "openback/app_auth/verifier.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <map>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "openback-app-auth-cpp requires OpenSSL 1.1.1 or newer"
#endif

#include "openback/app_auth/jwt.hpp"
#include "internal.hpp"

namespace openback::app_auth {

using detail::json;

namespace {

using PublicKey = std::shared_ptr<EVP_PKEY>;

constexpr std::size_t kMaxTokenLength = 16 * 1024;

enum class TokenKind { Access, Id };

[[noreturn]] void refuse(const char* reason, const char* message) { throw TokenVerificationError(reason, message); }

// An EC P-256 public key from a JWK {kty: EC, crv: P-256, x, y}; null when the JWK is not one.
PublicKey key_from_jwk(const json& jwk) {
    if (!jwk.is_object()) return nullptr;
    if (detail::string_or(jwk, "kty") != "EC" || detail::string_or(jwk, "crv") != "P-256") return nullptr;
    if (const auto alg = detail::opt_string(jwk, "alg"); alg && *alg != "ES256") return nullptr;
    if (const auto use = detail::opt_string(jwk, "use"); use && *use != "sig") return nullptr;
    std::string x;
    std::string y;
    try {
        x = base64url_decode(detail::string_or(jwk, "x"));
        y = base64url_decode(detail::string_or(jwk, "y"));
    } catch (const std::invalid_argument&) {
        return nullptr;
    }
    if (x.size() != 32 || y.size() != 32) return nullptr;
    unsigned char point[65];
    point[0] = 0x04;  // uncompressed point: 04 || X || Y
    std::memcpy(point + 1, x.data(), 32);
    std::memcpy(point + 33, y.data(), 32);

    EVP_PKEY* pkey = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    static const char group[] = "prime256v1";
    if (builder != nullptr &&
        OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, group, 0) == 1 &&
        OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point)) == 1 &&
        (params = OSSL_PARAM_BLD_to_param(builder)) != nullptr &&
        (ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)) != nullptr && EVP_PKEY_fromdata_init(ctx) == 1) {
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) pkey = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
#else
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* bx = BN_bin2bn(point + 1, 32, nullptr);
    BIGNUM* by = BN_bin2bn(point + 33, 32, nullptr);
    if (ec != nullptr && bx != nullptr && by != nullptr && EC_KEY_set_public_key_affine_coordinates(ec, bx, by) == 1) {
        pkey = EVP_PKEY_new();
        if (pkey != nullptr && EVP_PKEY_assign_EC_KEY(pkey, ec) == 1) {
            ec = nullptr;  // owned by pkey now
        } else {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }
    BN_free(bx);
    BN_free(by);
    EC_KEY_free(ec);
#endif
    if (pkey == nullptr) return nullptr;
    // The point must be on the curve (an invalid-curve key must never be used).
    EVP_PKEY_CTX* check = EVP_PKEY_CTX_new(pkey, nullptr);
    const bool valid = check != nullptr && EVP_PKEY_public_check(check) == 1;
    EVP_PKEY_CTX_free(check);
    if (!valid) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return PublicKey(pkey, EVP_PKEY_free);
}

// ES256: the JOSE signature is R || S (32 + 32 bytes); OpenSSL wants a DER ECDSA-Sig-Value.
bool verify_es256(EVP_PKEY* key, std::string_view signing_input, const std::string& signature) {
    if (signature.size() != 64) return false;
    const auto* raw = reinterpret_cast<const unsigned char*>(signature.data());
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (sig == nullptr) return false;
    BIGNUM* r = BN_bin2bn(raw, 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw + 32, 32, nullptr);
    if (r == nullptr || s == nullptr || ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return false;
    }
    int length = i2d_ECDSA_SIG(sig, nullptr);
    if (length <= 0) {
        ECDSA_SIG_free(sig);
        return false;
    }
    std::vector<unsigned char> der(static_cast<std::size_t>(length));
    unsigned char* out = der.data();
    length = i2d_ECDSA_SIG(sig, &out);
    ECDSA_SIG_free(sig);
    if (length <= 0) return false;

    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (md == nullptr) return false;
    const bool ok =
        EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestVerify(md, der.data(), static_cast<std::size_t>(length),
                         reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size()) == 1;
    EVP_MD_CTX_free(md);
    return ok;
}

std::map<std::string, PublicKey> keys_from_jwks(const json& jwks) {
    std::map<std::string, PublicKey> keys;
    if (!jwks.is_object()) return keys;
    const auto list = jwks.find("keys");
    if (list == jwks.end() || !list->is_array()) return keys;
    for (const auto& jwk : *list) {
        PublicKey key = key_from_jwk(jwk);
        if (key) keys.emplace(detail::string_or(jwk, "kid"), std::move(key));
    }
    return keys;
}

bool number_claim(const json& claims, const char* name, double& out) {
    const auto it = claims.find(name);
    if (it == claims.end()) return false;
    if (!it->is_number()) refuse("malformed", "A time claim is not a number");
    out = it->get<double>();
    return true;
}

}  // namespace

// --- AppUser -------------------------------------------------------------------------------------------------------

bool AppUser::has_role(std::string_view role) const {
    return std::any_of(roles.begin(), roles.end(), [role](const std::string& r) { return r == role; });
}

bool AppUser::has_permission(std::string_view permission) const {
    return std::any_of(permissions.begin(), permissions.end(),
                       [permission](const std::string& p) { return p == permission || p == "*"; });
}

AppUser AppUser::from_claims(const json& claims) {
    AppUser user;
    if (!claims.is_object()) return user;
    user.claims = claims;
    user.id = detail::string_or(claims, "sub");
    user.pool_id = detail::string_or(claims, "pool");
    const auto aud = claims.find("aud");
    if (aud != claims.end()) {
        if (aud->is_string()) {
            user.client_id = aud->get<std::string>();
        } else if (aud->is_array() && !aud->empty() && aud->front().is_string()) {
            user.client_id = aud->front().get<std::string>();
        }
    }
    user.email = detail::opt_string(claims, "email");
    user.email_verified = detail::bool_or(claims, "email_verified");
    user.anonymous = detail::bool_or(claims, "anon");
    user.org_id = detail::opt_string(claims, "org_id");
    user.roles = detail::string_list(claims, "roles");
    user.permissions = detail::string_list(claims, "permissions");
    const auto attr = claims.find("attr");
    if (attr != claims.end() && attr->is_object()) user.attributes = *attr;
    user.session_id = detail::opt_string(claims, "sid");
    user.amr = detail::string_list(claims, "amr");
    return user;
}

// --- TokenVerifier -------------------------------------------------------------------------------------------------

struct TokenVerifier::Impl {
    std::string issuer;
    VerifierOptions options;
    std::string jwks_uri;
    std::shared_ptr<HttpTransport> http;

    std::mutex mutex;        // the cache below
    std::mutex fetch_mutex;  // one JWKS request at a time
    std::map<std::string, PublicKey> keys;
    bool loaded = false;     // keys were fetched (or set) at least once
    std::chrono::system_clock::time_point fetched_at{};
    bool attempted = false;  // a fetch was attempted
    std::chrono::system_clock::time_point last_attempt{};

    std::chrono::system_clock::time_point now() const { return detail::now(options.clock); }

    // GET the JWKS; true when it worked. Keeps the old keys when it fails; throws jwks_unavailable only when there
    // are no keys at all.
    bool fetch(std::chrono::system_clock::time_point at) {
        HttpRequest request;
        request.method = "GET";
        request.url = jwks_uri;
        request.timeout = options.timeout;
        request.headers.emplace_back("Accept", "application/json");
        bool ok = false;
        std::map<std::string, PublicKey> fresh;
        try {
            const HttpResponse response = detail::send_checked(*http, request);
            if (response.ok()) {
                const json body = detail::parse_json_or_null(response.body);
                if (body.is_object()) {
                    fresh = keys_from_jwks(body);
                    ok = true;
                }
            }
        } catch (const AppAuthError&) {
            ok = false;
        }
        std::lock_guard<std::mutex> lock(mutex);
        attempted = true;
        last_attempt = at;
        if (ok) {
            keys = std::move(fresh);
            loaded = true;
            fetched_at = at;
            return true;
        }
        if (!loaded) throw AppAuthError(503, "jwks_unavailable", "The pool's signing keys could not be fetched");
        return false;
    }

    // The key for `kid`: from the cache; fetched again when the cache is old (every jwks_cache_ttl) or the kid is
    // unknown (at most once per unknown_kid_refetch_interval). Null when unknown.
    PublicKey key_for(const std::string& kid) {
        const auto t = now();
        {
            std::lock_guard<std::mutex> lock(mutex);
            const auto it = keys.find(kid);
            const bool stale = !loaded || t - fetched_at >= options.jwks_cache_ttl;
            const bool may_fetch = !attempted || t - last_attempt >= options.unknown_kid_refetch_interval;
            if (it != keys.end() && (!stale || !may_fetch)) return it->second;
            if (!may_fetch) {
                if (!loaded) throw AppAuthError(503, "jwks_unavailable", "The pool's signing keys could not be fetched");
                return nullptr;
            }
        }
        std::lock_guard<std::mutex> fetch_lock(fetch_mutex);
        {
            // Another thread may have fetched while this one waited for the lock: use its result.
            std::lock_guard<std::mutex> lock(mutex);
            if (attempted && t - last_attempt < options.unknown_kid_refetch_interval) {
                const auto it = keys.find(kid);
                if (it != keys.end()) return it->second;
                if (!loaded) throw AppAuthError(503, "jwks_unavailable", "The pool's signing keys could not be fetched");
                return nullptr;
            }
        }
        fetch(t);
        std::lock_guard<std::mutex> lock(mutex);
        const auto it = keys.find(kid);
        return it == keys.end() ? nullptr : it->second;
    }

    json verify(std::string_view token, TokenKind kind, const std::optional<std::string>& expected_nonce) {
        if (token.empty() || token.size() > kMaxTokenLength) refuse("malformed", "The token is empty or too long");
        const std::size_t first = token.find('.');
        const std::size_t second = first == std::string_view::npos ? first : token.find('.', first + 1);
        if (first == std::string_view::npos || second == std::string_view::npos ||
            token.find('.', second + 1) != std::string_view::npos) {
            refuse("malformed", "The token is not a JWT");
        }
        const std::string_view header_part = token.substr(0, first);
        const std::string_view payload_part = token.substr(first + 1, second - first - 1);
        const std::string_view signature_part = token.substr(second + 1);
        if (header_part.empty() || payload_part.empty() || signature_part.empty()) {
            refuse("malformed", "The token is not a signed JWT");
        }
        json header;
        json claims;
        std::string signature;
        try {
            header = json::parse(base64url_decode(header_part));
            claims = json::parse(base64url_decode(payload_part));
            signature = base64url_decode(signature_part);
        } catch (const std::exception&) {
            refuse("malformed", "The token is not a valid JWT");
        }
        if (!header.is_object() || !claims.is_object()) refuse("malformed", "The token is not a valid JWT");

        // Header: ES256 only (never "none", HS*, RS*: algorithm confusion), the expected type, no critical extensions.
        if (detail::opt_string(header, "alg").value_or("") != "ES256") {
            refuse("unsupported_alg", "Only ES256 tokens are accepted");
        }
        if (header.contains("crit")) refuse("unsupported_header", "Critical header extensions are not supported");
        const std::optional<std::string> typ = detail::opt_string(header, "typ");
        if (header.contains("typ") && !typ) refuse("wrong_type", "Invalid token type");
        if (kind == TokenKind::Access) {
            const std::string t = typ ? detail::to_lower(*typ) : std::string();
            if (t != "at+jwt" && t != "application/at+jwt") refuse("wrong_type", "Not an access token (typ at+jwt)");
        } else if (typ) {
            const std::string t = detail::to_lower(*typ);
            if (t != "jwt" && t != "application/jwt") refuse("wrong_type", "Not an ID token (typ JWT)");
        }
        if (header.contains("kid") && !header["kid"].is_string()) refuse("malformed", "Invalid key id");
        const std::string kid = detail::string_or(header, "kid");

        // Signature.
        const PublicKey key = key_for(kid);
        if (!key) refuse("unknown_key", "The token's signing key is unknown");
        if (!verify_es256(key.get(), token.substr(0, second), signature)) refuse("bad_signature", "Invalid signature");

        // Claims.
        if (detail::opt_string(claims, "iss").value_or("") != issuer) refuse("wrong_issuer", "The token has another issuer");
        bool audience_ok = false;
        const auto aud = claims.find("aud");
        if (aud != claims.end()) {
            const auto accepted = [this](const std::string& value) {
                return std::find(options.audiences.begin(), options.audiences.end(), value) != options.audiences.end();
            };
            if (aud->is_string()) {
                audience_ok = accepted(aud->get<std::string>());
            } else if (aud->is_array()) {
                for (const auto& item : *aud) {
                    if (item.is_string() && accepted(item.get<std::string>())) audience_ok = true;
                }
            }
        }
        if (!audience_ok) refuse("wrong_audience", "The token is for another app");

        const double now_s = static_cast<double>(
            std::chrono::duration_cast<std::chrono::seconds>(now().time_since_epoch()).count());
        const double leeway = static_cast<double>(options.leeway.count());
        double exp = 0;
        if (!number_claim(claims, "exp", exp)) refuse("malformed", "The token has no expiry");
        if (now_s >= exp + leeway) refuse("expired", "The token has expired");
        double nbf = 0;
        if (number_claim(claims, "nbf", nbf) && now_s + leeway < nbf) refuse("not_yet_valid", "The token is not valid yet");
        double iat = 0;
        if (number_claim(claims, "iat", iat) && iat > now_s + leeway) refuse("issued_in_future", "The token was issued in the future");
        if (detail::string_or(claims, "sub").empty()) refuse("missing_subject", "The token has no subject");

        if (kind == TokenKind::Id && expected_nonce) {
            const std::optional<std::string> nonce = detail::opt_string(claims, "nonce");
            if (!nonce || expected_nonce->empty() || !detail::constant_time_equals(*nonce, *expected_nonce)) {
                refuse("nonce_mismatch", "The ID token's nonce does not match");
            }
        }
        return claims;
    }
};

TokenVerifier::TokenVerifier(std::string issuer, VerifierOptions options) : impl_(std::make_shared<Impl>()) {
    impl_->issuer = detail::strip_trailing_slashes(std::move(issuer));
    if (impl_->issuer.empty()) throw std::invalid_argument("openback::app_auth::TokenVerifier: issuer is required");
    if (options.audiences.empty()) {
        throw std::invalid_argument("openback::app_auth::TokenVerifier: at least one audience (client ID) is required");
    }
    impl_->jwks_uri = options.jwks_uri ? *options.jwks_uri : impl_->issuer + "/.well-known/jwks.json";
    impl_->http = options.http ? options.http : default_transport();
    impl_->options = std::move(options);
}

const std::string& TokenVerifier::issuer() const noexcept { return impl_->issuer; }

AppUser TokenVerifier::verify(std::string_view access_token) const {
    const json claims = impl_->verify(access_token, TokenKind::Access, std::nullopt);
    AppUser user = AppUser::from_claims(claims);
    // The client ID is the audience that matched.
    const auto aud = claims.find("aud");
    if (aud != claims.end() && aud->is_array()) {
        for (const auto& item : *aud) {
            if (!item.is_string()) continue;
            const std::string value = item.get<std::string>();
            const auto& accepted = impl_->options.audiences;
            if (std::find(accepted.begin(), accepted.end(), value) != accepted.end()) {
                user.client_id = value;
                break;
            }
        }
    }
    return user;
}

json TokenVerifier::verify_access_token_claims(std::string_view access_token) const {
    return impl_->verify(access_token, TokenKind::Access, std::nullopt);
}

json TokenVerifier::verify_id_token(std::string_view id_token, const std::optional<std::string>& expected_nonce) const {
    return impl_->verify(id_token, TokenKind::Id, expected_nonce);
}

void TokenVerifier::set_jwks(const json& jwks) const {
    std::map<std::string, PublicKey> keys = keys_from_jwks(jwks);
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->keys = std::move(keys);
    impl_->loaded = true;
    impl_->fetched_at = impl_->now();
}

void TokenVerifier::refresh_jwks() const {
    std::lock_guard<std::mutex> fetch_lock(impl_->fetch_mutex);
    if (!impl_->fetch(impl_->now())) {
        throw AppAuthError(503, "jwks_unavailable", "The pool's signing keys could not be fetched");
    }
}

}  // namespace openback::app_auth
