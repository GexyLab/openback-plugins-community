// openback-app-auth-cpp -- errors.
#pragma once

#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace openback::app_auth {

/// Every failure of the SDK: an error answer of the user pool, a network failure (status 0, code "network_error"),
/// a failed check of a sign-in callback (status 400) or of a token (TokenVerificationError, status 401).
///
///  - status():  the HTTP status (0 when no answer was received);
///  - code():    the pool's error code ("invalid_credentials", "weak_password", "token_expired", ...) or the OAuth
///               error ("invalid_grant", "login_required", ...); "http_<status>" when the answer carried none;
///  - what():    a human-readable message (never contains tokens, codes or passwords);
///  - detail():  the answer's "detail" (e.g. {"code": "weak_password", "problems": [...]}) or null.
class AppAuthError : public std::runtime_error {
public:
    AppAuthError(int status, std::string code, const std::string& message, nlohmann::json detail = nullptr);

    int status() const noexcept { return status_; }
    const std::string& code() const noexcept { return code_; }
    std::string message() const { return what(); }
    const nlohmann::json& detail() const noexcept { return detail_; }

    /// True when the request never got an answer (connection refused, DNS, TLS, timeout...).
    bool is_network_error() const noexcept { return status_ == 0; }

private:
    int status_;
    std::string code_;
    nlohmann::json detail_;
};

/// A token refused by TokenVerifier: status 401, code "invalid_token", reason() says why
/// ("malformed", "unsupported_alg", "wrong_type", "unknown_key", "bad_signature", "wrong_issuer", "wrong_audience",
/// "expired", "not_yet_valid", "issued_in_future", "missing_subject", "nonce_mismatch", "unsupported_header").
class TokenVerificationError : public AppAuthError {
public:
    TokenVerificationError(std::string reason, const std::string& message);

    const std::string& reason() const noexcept { return reason_; }

private:
    std::string reason_;
};

}  // namespace openback::app_auth
