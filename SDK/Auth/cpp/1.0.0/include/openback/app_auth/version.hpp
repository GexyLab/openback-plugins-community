// openback-app-auth-cpp -- version of the library.
#pragma once

#define OPENBACK_APP_AUTH_VERSION_MAJOR 1
#define OPENBACK_APP_AUTH_VERSION_MINOR 0
#define OPENBACK_APP_AUTH_VERSION_PATCH 0
#define OPENBACK_APP_AUTH_VERSION "1.0.0"

namespace openback::app_auth {

/// The library's version, "1.0.0".
constexpr const char* version() noexcept { return OPENBACK_APP_AUTH_VERSION; }

}  // namespace openback::app_auth
