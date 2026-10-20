// openback-app-auth-cpp -- base64url and unverified JWT decoding.
#include "openback/app_auth/jwt.hpp"

#include <cstdint>
#include <exception>
#include <stdexcept>
#include <utility>

namespace openback::app_auth {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int value_of(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

std::optional<nlohmann::json> decode_part(std::string_view token, int index) {
    const auto first = token.find('.');
    if (first == std::string_view::npos) return std::nullopt;
    const auto second = token.find('.', first + 1);
    if (second == std::string_view::npos || token.find('.', second + 1) != std::string_view::npos) return std::nullopt;
    const std::string_view part = index == 0 ? token.substr(0, first) : token.substr(first + 1, second - first - 1);
    try {
        nlohmann::json value = nlohmann::json::parse(base64url_decode(part));
        if (!value.is_object()) return std::nullopt;
        return std::optional<nlohmann::json>(std::move(value));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace

std::string base64url_encode(std::string_view bytes) {
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 2 < bytes.size(); i += 3) {
        const std::uint32_t n = (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16) |
                                (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8) |
                                static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 2]));
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
        out.push_back(kAlphabet[(n >> 6) & 63]);
        out.push_back(kAlphabet[n & 63]);
    }
    const std::size_t rest = bytes.size() - i;
    if (rest == 1) {
        const std::uint32_t n = static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16;
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
    } else if (rest == 2) {
        const std::uint32_t n = (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16) |
                                (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8);
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
        out.push_back(kAlphabet[(n >> 6) & 63]);
    }
    return out;
}

std::string base64url_decode(std::string_view text) {
    if (text.size() % 4 == 1) throw std::invalid_argument("invalid base64url length");
    std::string out;
    out.reserve(text.size() * 3 / 4);
    std::uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        const int v = value_of(c);
        if (v < 0) throw std::invalid_argument("invalid base64url character");
        buffer = ((buffer << 6) | static_cast<std::uint32_t>(v)) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFFu));
        }
    }
    return out;
}

std::optional<nlohmann::json> decode_jwt_header(std::string_view token) { return decode_part(token, 0); }

std::optional<nlohmann::json> decode_jwt_payload(std::string_view token) { return decode_part(token, 1); }

}  // namespace openback::app_auth
