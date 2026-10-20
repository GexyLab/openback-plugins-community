// openback-app-auth-cpp -- where the Client keeps its session.
#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace openback::app_auth {

/// A string store by key. The Client keeps its session (JSON: accessToken, refreshToken, idToken, expiresAt, user,
/// org) under "openback.auth.<client id>" and a pending hosted sign-in under "<that key>.pkce".
///
/// The values are secrets: a persistent implementation must protect them (OS keychain / credential vault, a file
/// readable only by the user, an encrypted database column). set() must replace the value atomically: the refresh
/// token rotates at every use and an old one presented again ends the session.
/// Implementations must be safe to call from several threads at once.
class TokenStorage {
public:
    virtual ~TokenStorage() = default;
    virtual std::optional<std::string> get(const std::string& key) = 0;
    virtual void set(const std::string& key, const std::string& value) = 0;
    virtual void remove(const std::string& key) = 0;
};

/// The default: in memory, lost when the process ends.
class MemoryTokenStorage : public TokenStorage {
public:
    std::optional<std::string> get(const std::string& key) override;
    void set(const std::string& key, const std::string& value) override;
    void remove(const std::string& key) override;

private:
    std::mutex mutex_;
    std::map<std::string, std::string> values_;
};

}  // namespace openback::app_auth
