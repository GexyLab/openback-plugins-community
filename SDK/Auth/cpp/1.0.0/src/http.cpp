// openback-app-auth-cpp -- HTTP request / response helpers.
#include "openback/app_auth/http.hpp"

#include <algorithm>

#include "internal.hpp"

namespace openback::app_auth {

namespace {

std::string find_header(const HttpHeaders& headers, std::string_view name) {
    for (const auto& header : headers) {
        if (detail::iequals(header.first, name)) return header.second;
    }
    return {};
}

}  // namespace

void HttpRequest::set_header(const std::string& name, const std::string& value) {
    headers.erase(std::remove_if(headers.begin(), headers.end(),
                                 [&name](const std::pair<std::string, std::string>& header) {
                                     return detail::iequals(header.first, name);
                                 }),
                  headers.end());
    headers.emplace_back(name, value);
}

std::string HttpRequest::header(std::string_view name) const { return find_header(headers, name); }

std::string HttpResponse::header(std::string_view name) const { return find_header(headers, name); }

}  // namespace openback::app_auth
