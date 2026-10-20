// openback-app-auth-cpp -- the HTTP layer. The SDK sends every request through an HttpTransport: the default one uses
// libcurl; tests, embedded targets and apps with their own HTTP stack inject their own implementation.
#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace openback::app_auth {

using HttpHeaders = std::vector<std::pair<std::string, std::string>>;

struct HttpRequest {
    std::string method = "GET";                 // GET, POST, PATCH, DELETE
    std::string url;                            // absolute https:// (or http:// for localhost) URL
    HttpHeaders headers;
    std::string body;                           // empty: no body
    std::chrono::milliseconds timeout{30000};   // whole request

    /// Sets a header, replacing any header with the same name (case-insensitive).
    void set_header(const std::string& name, const std::string& value);
    /// The value of a header (case-insensitive), empty when absent.
    std::string header(std::string_view name) const;
};

struct HttpResponse {
    int status = 0;
    HttpHeaders headers;
    std::string body;

    /// The value of a header (case-insensitive), empty when absent.
    std::string header(std::string_view name) const;
    bool ok() const noexcept { return status >= 200 && status < 300; }
};

/// Sends one request and returns the answer, whatever its status. Throws (any std::exception) when no answer was
/// received; the SDK turns it into AppAuthError{status 0, code "network_error"}. Implementations must be safe to call
/// from several threads at once and must NOT follow redirects.
class HttpTransport {
public:
    virtual ~HttpTransport() = default;
    virtual HttpResponse send(const HttpRequest& request) = 0;
};

struct CurlTransportOptions {
    std::string user_agent = "openback-app-auth-cpp/1.0.0";
    std::chrono::milliseconds connect_timeout{10000};
    std::string ca_info;   // CA bundle file (CURLOPT_CAINFO); empty: libcurl's default
    std::string ca_path;   // CA directory (CURLOPT_CAPATH); empty: libcurl's default
    std::string proxy;     // CURLOPT_PROXY; empty: libcurl's default (environment)
};

/// A libcurl transport (TLS peer and host verification always on, no redirects, http/https only). Throws
/// AppAuthError{code "no_transport"} when the library was built with OPENBACK_APP_AUTH_WITH_CURL=OFF.
std::shared_ptr<HttpTransport> make_curl_transport(CurlTransportOptions options = {});

/// The process-wide default transport (a libcurl one). Built without libcurl, its send() throws
/// AppAuthError{code "no_transport"}: pass your own HttpTransport in the options.
std::shared_ptr<HttpTransport> default_transport();

}  // namespace openback::app_auth
