// openback-app-auth-cpp -- the default HTTP transport (libcurl).
#include "openback/app_auth/http.hpp"

#include <stdexcept>

#include "openback/app_auth/error.hpp"
#include "openback/app_auth/version.hpp"

#ifndef OPENBACK_APP_AUTH_WITH_CURL
#define OPENBACK_APP_AUTH_WITH_CURL 0
#endif

#if OPENBACK_APP_AUTH_WITH_CURL

#include <cctype>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#include <curl/curl.h>

namespace openback::app_auth {

namespace {

std::once_flag g_curl_global_once;

void curl_global_once() {
    std::call_once(g_curl_global_once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

std::size_t on_body(char* data, std::size_t size, std::size_t count, void* user) {
    const std::size_t total = size * count;
    static_cast<std::string*>(user)->append(data, total);
    return total;
}

std::size_t on_header(char* data, std::size_t size, std::size_t count, void* user) {
    const std::size_t total = size * count;
    auto* headers = static_cast<HttpHeaders*>(user);
    std::string_view line(data, total);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.remove_suffix(1);
    if (line.size() >= 5 && line.compare(0, 5, "HTTP/") == 0) {
        headers->clear();  // a new status line (100 Continue, proxy CONNECT): only the final answer's headers count
        return total;
    }
    const auto colon = line.find(':');
    if (colon != std::string_view::npos && colon > 0) {
        std::string_view value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        headers->emplace_back(std::string(line.substr(0, colon)), std::string(value));
    }
    return total;
}

struct EasyDeleter {
    void operator()(CURL* handle) const noexcept { curl_easy_cleanup(handle); }
};

struct SlistDeleter {
    void operator()(curl_slist* list) const noexcept { curl_slist_free_all(list); }
};

std::string upper(std::string text) {
    for (auto& c : text) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return text;
}

class CurlTransport final : public HttpTransport {
public:
    explicit CurlTransport(CurlTransportOptions options) : options_(std::move(options)) { curl_global_once(); }

    HttpResponse send(const HttpRequest& request) override {
        char error_buffer[CURL_ERROR_SIZE];
        error_buffer[0] = '\0';
        HttpResponse response;

        curl_slist* list = nullptr;
        for (const auto& header : request.headers) {
            curl_slist* next = curl_slist_append(list, (header.first + ": " + header.second).c_str());
            if (next == nullptr) {
                curl_slist_free_all(list);
                throw std::runtime_error("Out of memory building the request headers");
            }
            list = next;
        }
        curl_slist* next = curl_slist_append(list, "Expect:");  // no "100-continue" round trip
        if (next != nullptr) list = next;
        std::unique_ptr<curl_slist, SlistDeleter> headers(list);

        std::unique_ptr<CURL, EasyDeleter> easy(curl_easy_init());
        if (!easy) throw std::runtime_error("curl_easy_init failed");
        CURL* h = easy.get();

        curl_easy_setopt(h, CURLOPT_URL, request.url.c_str());
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers.get());
        curl_easy_setopt(h, CURLOPT_ERRORBUFFER, error_buffer);
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
#if LIBCURL_VERSION_NUM >= 0x075500  // 7.85.0
        curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
#else
        curl_easy_setopt(h, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
        curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, static_cast<long>(request.timeout.count()));
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(options_.connect_timeout.count()));
        if (!options_.user_agent.empty()) curl_easy_setopt(h, CURLOPT_USERAGENT, options_.user_agent.c_str());
        if (!options_.ca_info.empty()) curl_easy_setopt(h, CURLOPT_CAINFO, options_.ca_info.c_str());
        if (!options_.ca_path.empty()) curl_easy_setopt(h, CURLOPT_CAPATH, options_.ca_path.c_str());
        if (!options_.proxy.empty()) curl_easy_setopt(h, CURLOPT_PROXY, options_.proxy.c_str());
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, &on_body);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, static_cast<void*>(&response.body));
        curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, &on_header);
        curl_easy_setopt(h, CURLOPT_HEADERDATA, static_cast<void*>(&response.headers));

        const std::string method = upper(request.method.empty() ? std::string("GET") : request.method);
        if (method == "GET") {
            curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
        } else {
            if (method == "POST") {
                curl_easy_setopt(h, CURLOPT_POST, 1L);
            } else {
                curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, method.c_str());
            }
            if (method == "POST" || !request.body.empty()) {
                curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
                curl_easy_setopt(h, CURLOPT_POSTFIELDS, request.body.c_str());
            }
        }

        const CURLcode rc = curl_easy_perform(h);
        if (rc != CURLE_OK) {
            throw std::runtime_error(error_buffer[0] != '\0' ? std::string(error_buffer)
                                                             : std::string(curl_easy_strerror(rc)));
        }
        long status = 0;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
        response.status = static_cast<int>(status);
        return response;
    }

private:
    CurlTransportOptions options_;
};

}  // namespace

std::shared_ptr<HttpTransport> make_curl_transport(CurlTransportOptions options) {
    return std::make_shared<CurlTransport>(std::move(options));
}

std::shared_ptr<HttpTransport> default_transport() {
    static const std::shared_ptr<HttpTransport> transport = make_curl_transport();
    return transport;
}

}  // namespace openback::app_auth

#else  // !OPENBACK_APP_AUTH_WITH_CURL

namespace openback::app_auth {

namespace {

class NoTransport final : public HttpTransport {
public:
    HttpResponse send(const HttpRequest&) override {
        throw AppAuthError(0, "no_transport",
                           "openback-app-auth-cpp was built without libcurl: pass an HttpTransport in the options");
    }
};

}  // namespace

std::shared_ptr<HttpTransport> make_curl_transport(CurlTransportOptions) {
    throw AppAuthError(0, "no_transport", "openback-app-auth-cpp was built without libcurl");
}

std::shared_ptr<HttpTransport> default_transport() {
    static const std::shared_ptr<HttpTransport> transport = std::make_shared<NoTransport>();
    return transport;
}

}  // namespace openback::app_auth

#endif
