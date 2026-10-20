// openback-app-auth-cpp -- internal helpers (not installed).
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "openback/app_auth/error.hpp"
#include "openback/app_auth/http.hpp"
#include "openback/app_auth/types.hpp"

namespace openback::app_auth::detail {

using json = nlohmann::json;
using FormFields = std::vector<std::pair<std::string, std::string>>;

// --- text ------------------------------------------------------------------------------------------------------------
std::string url_encode(std::string_view text);                      // RFC 3986: unreserved kept, the rest %XX
std::string url_decode(std::string_view text, bool plus_as_space);
std::string form_encode(const FormFields& fields);
std::string base64_encode(std::string_view bytes);                  // standard alphabet, padded
std::string strip_trailing_slashes(std::string text);
std::string to_lower(std::string_view text);
bool iequals(std::string_view a, std::string_view b) noexcept;
bool starts_with(std::string_view text, std::string_view prefix) noexcept;

// --- crypto (OpenSSL) ------------------------------------------------------------------------------------------------
std::string random_bytes(std::size_t count);                        // RAND_bytes
std::string sha256(std::string_view data);                          // raw 32 bytes
bool constant_time_equals(std::string_view a, std::string_view b) noexcept;

// --- time ------------------------------------------------------------------------------------------------------------
std::chrono::system_clock::time_point now(const ClockFn& clock);
std::int64_t to_epoch_ms(std::chrono::system_clock::time_point t);

// --- JSON ------------------------------------------------------------------------------------------------------------
json parse_json_or_null(const std::string& body);                   // null when empty or not JSON
std::optional<std::string> opt_string(const json& object, const char* key);
std::string string_or(const json& object, const char* key, const std::string& fallback = {});
bool bool_or(const json& object, const char* key, bool fallback = false);
std::optional<std::int64_t> opt_int(const json& object, const char* key);
std::vector<std::string> string_list(const json& object, const char* key);

// --- HTTP ------------------------------------------------------------------------------------------------------------
/// The pool's error answer as an AppAuthError: {"detail": {"code","message"}} | {"detail": "..."} | {"detail": [...]}
/// (FastAPI validation) | OAuth {"error","error_description"}.
AppAuthError error_from_response(const HttpResponse& response);

/// transport.send(), with any non-AppAuthError exception turned into AppAuthError{0, "network_error"}.
HttpResponse send_checked(HttpTransport& transport, const HttpRequest& request);

struct ClientCredentials {
    std::string client_id;
    std::optional<std::string> client_secret;  // none: a public client (client_id in the form)
    bool basic = true;                         // client_secret_basic (true) or client_secret_post
};

/// POST of a form to an OAuth endpoint with the client's authentication; the JSON answer (empty object when the
/// body is empty). Throws error_from_response() on a non-2xx status.
json post_form(HttpTransport& transport, const std::string& url, FormFields fields, const ClientCredentials& credentials,
               std::chrono::milliseconds timeout);

}  // namespace openback::app_auth::detail
