// openback-app-auth-cpp -- base64url and unverified JWT decoding. To TRUST a token use TokenVerifier.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace openback::app_auth {

/// base64url without padding (RFC 4648 section 5).
std::string base64url_encode(std::string_view bytes);

/// Decodes base64url (padding not allowed). Throws std::invalid_argument on a character outside the alphabet or an
/// impossible length.
std::string base64url_decode(std::string_view text);

/// The header of a JWT, NOT verified; nullopt when it is not a JWT.
std::optional<nlohmann::json> decode_jwt_header(std::string_view token);

/// The claims of a JWT, NOT verified (for display, e.g. Client::access_token_claims); nullopt when it is not a JWT.
std::optional<nlohmann::json> decode_jwt_payload(std::string_view token);

}  // namespace openback::app_auth
