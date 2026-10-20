// openback-app-auth-cpp -- internal helpers.
#include "internal.hpp"

#include <algorithm>
#include <exception>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace openback::app_auth::detail {

namespace {

constexpr char kHex[] = "0123456789ABCDEF";
constexpr char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool is_unreserved(unsigned char c) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char ascii_lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

}  // namespace

std::string url_encode(std::string_view text) {
    std::string out;
    out.reserve(text.size() * 3);
    for (char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (is_unreserved(c)) {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

std::string url_decode(std::string_view text, bool plus_as_space) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '%' && i + 2 < text.size()) {
            const int hi = hex_value(text[i + 1]);
            const int lo = hex_value(text[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
            out.push_back(c);
        } else if (c == '+' && plus_as_space) {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::string form_encode(const FormFields& fields) {
    std::string out;
    for (const auto& [name, value] : fields) {
        if (!out.empty()) out.push_back('&');
        out += url_encode(name);
        out.push_back('=');
        out += url_encode(value);
    }
    return out;
}

std::string base64_encode(std::string_view bytes) {
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 2 < bytes.size(); i += 3) {
        const std::uint32_t n = (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16) |
                                (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8) |
                                static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 2]));
        out.push_back(kBase64[(n >> 18) & 63]);
        out.push_back(kBase64[(n >> 12) & 63]);
        out.push_back(kBase64[(n >> 6) & 63]);
        out.push_back(kBase64[n & 63]);
    }
    const std::size_t rest = bytes.size() - i;
    if (rest == 1) {
        const std::uint32_t n = static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16;
        out.push_back(kBase64[(n >> 18) & 63]);
        out.push_back(kBase64[(n >> 12) & 63]);
        out += "==";
    } else if (rest == 2) {
        const std::uint32_t n = (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16) |
                                (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8);
        out.push_back(kBase64[(n >> 18) & 63]);
        out.push_back(kBase64[(n >> 12) & 63]);
        out.push_back(kBase64[(n >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::string strip_trailing_slashes(std::string text) {
    while (!text.empty() && text.back() == '/') text.pop_back();
    return text;
}

std::string to_lower(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), ascii_lower);
    return out;
}

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    }
    return true;
}

bool starts_with(std::string_view text, std::string_view prefix) noexcept {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::string random_bytes(std::size_t count) {
    std::string out(count, '\0');
    if (count == 0) return out;
    if (count > 4096 ||
        RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(count)) != 1) {
        throw AppAuthError(0, "crypto_error", "The random generator failed");
    }
    return out;
}

std::string sha256(std::string_view data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), nullptr) != 1) {
        throw AppAuthError(0, "crypto_error", "SHA-256 failed");
    }
    return std::string(reinterpret_cast<const char*>(digest), length);
}

bool constant_time_equals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::chrono::system_clock::time_point now(const ClockFn& clock) {
    return clock ? clock() : std::chrono::system_clock::now();
}

std::int64_t to_epoch_ms(std::chrono::system_clock::time_point t) {
    return static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
}

json parse_json_or_null(const std::string& body) {
    if (body.empty()) return json(nullptr);
    json value = json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (value.is_discarded()) return json(nullptr);
    return value;
}

std::optional<std::string> opt_string(const json& object, const char* key) {
    if (!object.is_object()) return std::nullopt;
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

std::string string_or(const json& object, const char* key, const std::string& fallback) {
    auto value = opt_string(object, key);
    return value ? *value : fallback;
}

bool bool_or(const json& object, const char* key, bool fallback) {
    if (!object.is_object()) return fallback;
    const auto it = object.find(key);
    if (it == object.end() || !it->is_boolean()) return fallback;
    return it->get<bool>();
}

std::optional<std::int64_t> opt_int(const json& object, const char* key) {
    if (!object.is_object()) return std::nullopt;
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number()) return std::nullopt;
    if (it->is_number_float()) return static_cast<std::int64_t>(it->get<double>());
    return it->get<std::int64_t>();
}

std::vector<std::string> string_list(const json& object, const char* key) {
    std::vector<std::string> out;
    if (!object.is_object()) return out;
    const auto it = object.find(key);
    if (it == object.end() || !it->is_array()) return out;
    for (const auto& item : *it) {
        if (item.is_string()) out.push_back(item.get<std::string>());
    }
    return out;
}

AppAuthError error_from_response(const HttpResponse& response) {
    const json data = parse_json_or_null(response.body);
    std::string code;
    std::string message;
    json detail = nullptr;
    if (data.is_object()) {
        const auto d = data.find("detail");
        if (d != data.end()) {
            detail = *d;
            if (d->is_object()) {
                code = string_or(*d, "code");
                message = string_or(*d, "message");
            } else if (d->is_string()) {
                message = d->get<std::string>();
            } else if (d->is_array() && !d->empty() && d->front().is_object()) {
                message = string_or(d->front(), "msg");
                code = "validation_error";
            }
        } else if (auto oauth = opt_string(data, "error")) {
            code = *oauth;
            message = string_or(data, "error_description");
            detail = data;
        }
    }
    if (code.empty()) code = "http_" + std::to_string(response.status);
    if (message.empty()) message = code;
    return AppAuthError(response.status, code, message, detail);
}

HttpResponse send_checked(HttpTransport& transport, const HttpRequest& request) {
    try {
        return transport.send(request);
    } catch (const AppAuthError&) {
        throw;
    } catch (const std::exception& e) {
        throw AppAuthError(0, "network_error", std::string("Network error: ") + e.what());
    } catch (...) {
        throw AppAuthError(0, "network_error", "Network error");
    }
}

json post_form(HttpTransport& transport, const std::string& url, FormFields fields, const ClientCredentials& credentials,
               std::chrono::milliseconds timeout) {
    HttpRequest request;
    request.method = "POST";
    request.url = url;
    request.timeout = timeout;
    request.headers.emplace_back("Content-Type", "application/x-www-form-urlencoded");
    request.headers.emplace_back("Accept", "application/json");
    if (credentials.client_secret && credentials.basic) {
        const std::string pair = url_encode(credentials.client_id) + ":" + url_encode(*credentials.client_secret);
        request.headers.emplace_back("Authorization", "Basic " + base64_encode(pair));
    } else {
        fields.emplace_back("client_id", credentials.client_id);
        if (credentials.client_secret) fields.emplace_back("client_secret", *credentials.client_secret);
    }
    request.body = form_encode(fields);
    const HttpResponse response = send_checked(transport, request);
    if (!response.ok()) throw error_from_response(response);
    json data = parse_json_or_null(response.body);
    if (data.is_null()) data = json::object();
    return data;
}

}  // namespace openback::app_auth::detail
