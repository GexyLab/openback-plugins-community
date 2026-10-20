// openback-app-auth-cpp -- the in-memory token storage.
#include "openback/app_auth/storage.hpp"

namespace openback::app_auth {

std::optional<std::string> MemoryTokenStorage::get(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = values_.find(key);
    if (it == values_.end()) return std::nullopt;
    return it->second;
}

void MemoryTokenStorage::set(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    values_[key] = value;
}

void MemoryTokenStorage::remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    values_.erase(key);
}

}  // namespace openback::app_auth
