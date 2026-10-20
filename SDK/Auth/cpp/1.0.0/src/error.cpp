// openback-app-auth-cpp -- errors.
#include "openback/app_auth/error.hpp"

#include <utility>

namespace openback::app_auth {

namespace {

std::string pick_message(int status, const std::string& code, const std::string& message) {
    if (!message.empty()) return message;
    if (!code.empty()) return code;
    return "HTTP " + std::to_string(status);
}

}  // namespace

AppAuthError::AppAuthError(int status, std::string code, const std::string& message, nlohmann::json detail)
    : std::runtime_error(pick_message(status, code, message)),
      status_(status),
      code_(std::move(code)),
      detail_(std::move(detail)) {
    if (code_.empty()) code_ = "http_" + std::to_string(status);
}

TokenVerificationError::TokenVerificationError(std::string reason, const std::string& message)
    : AppAuthError(401, "invalid_token", message, nlohmann::json{{"reason", reason}}), reason_(std::move(reason)) {}

}  // namespace openback::app_auth
