// openback-app-auth-cpp -- parsing of the pool's answers.
#include "openback/app_auth/types.hpp"

#include "internal.hpp"

namespace openback::app_auth {

using detail::bool_or;
using detail::json;
using detail::opt_int;
using detail::opt_string;
using detail::string_list;
using detail::string_or;

namespace {

const json* child_object(const json& value, const char* key) {
    if (!value.is_object()) return nullptr;
    const auto it = value.find(key);
    if (it == value.end() || !it->is_object()) return nullptr;
    return &*it;
}

}  // namespace

PoolUser PoolUser::from_json(const json& value) {
    PoolUser user;
    if (!value.is_object()) return user;
    user.raw = value;
    user.id = string_or(value, "id");
    user.email = opt_string(value, "email");
    user.email_verified = bool_or(value, "email_verified");
    user.display_name = string_or(value, "display_name");
    user.photo_url = opt_string(value, "photo_url");
    user.locale = opt_string(value, "locale");
    if (const json* attributes = child_object(value, "attributes")) user.attributes = *attributes;
    user.anonymous = bool_or(value, "anonymous");
    user.created_at = opt_string(value, "created_at");
    user.last_login_at = opt_string(value, "last_login_at");
    if (const json* mfa = child_object(value, "mfa")) user.mfa_totp = bool_or(*mfa, "totp");
    user.org_id = opt_string(value, "org_id");
    user.roles = string_list(value, "roles");
    const auto providers = value.find("providers");
    if (providers != value.end() && providers->is_array()) {
        for (const auto& item : *providers) {
            if (!item.is_object()) continue;
            user.providers.push_back(LinkedProvider{string_or(item, "provider_id"), string_or(item, "kind")});
        }
    }
    const auto has_password = value.find("has_password");
    if (has_password != value.end() && has_password->is_boolean()) user.has_password = has_password->get<bool>();
    return user;
}

ActiveOrg ActiveOrg::from_json(const json& value) {
    ActiveOrg org;
    if (!value.is_object()) return org;
    org.raw = value;
    org.id = string_or(value, "id");
    org.name = string_or(value, "name");
    org.roles = string_list(value, "roles");
    org.choices = static_cast<int>(opt_int(value, "choices").value_or(0));
    return org;
}

const char* to_string(OutcomeStatus status) noexcept {
    switch (status) {
        case OutcomeStatus::Ok: return "ok";
        case OutcomeStatus::VerificationRequired: return "verification_required";
        case OutcomeStatus::MfaRequired: return "mfa_required";
        case OutcomeStatus::MfaEnrollRequired: return "mfa_enroll_required";
        case OutcomeStatus::PasswordChangeRequired: return "password_change_required";
        case OutcomeStatus::Unknown: break;
    }
    return "unknown";
}

OutcomeStatus outcome_status_from_string(std::string_view status) noexcept {
    if (status == "ok") return OutcomeStatus::Ok;
    if (status == "verification_required") return OutcomeStatus::VerificationRequired;
    if (status == "mfa_required") return OutcomeStatus::MfaRequired;
    if (status == "mfa_enroll_required") return OutcomeStatus::MfaEnrollRequired;
    if (status == "password_change_required") return OutcomeStatus::PasswordChangeRequired;
    return OutcomeStatus::Unknown;
}

Outcome Outcome::from_json(const json& value) {
    Outcome outcome;
    if (!value.is_object()) return outcome;
    outcome.status_name = string_or(value, "status");
    outcome.status = outcome_status_from_string(outcome.status_name);
    if (const json* user = child_object(value, "user")) outcome.user = PoolUser::from_json(*user);
    if (const json* org = child_object(value, "org")) outcome.org = ActiveOrg::from_json(*org);
    outcome.mfa_token = opt_string(value, "mfa_token");
    outcome.change_token = opt_string(value, "change_token");
    outcome.recovery_codes = string_list(value, "recovery_codes");
    outcome.raw = value;
    outcome.raw.erase("access_token");
    outcome.raw.erase("refresh_token");
    outcome.raw.erase("id_token");
    return outcome;
}

TokenSet TokenSet::from_json(const json& value) {
    TokenSet tokens;
    if (!value.is_object()) return tokens;
    tokens.access_token = string_or(value, "access_token");
    tokens.token_type = string_or(value, "token_type", "Bearer");
    tokens.expires_in = opt_int(value, "expires_in").value_or(0);
    tokens.scope = string_or(value, "scope");
    tokens.refresh_token = string_or(value, "refresh_token");
    tokens.refresh_expires_in = opt_int(value, "refresh_expires_in");
    tokens.id_token = opt_string(value, "id_token");
    if (const json* org = child_object(value, "org")) tokens.org = ActiveOrg::from_json(*org);
    return tokens;
}

Organization Organization::from_json(const json& value) {
    Organization org;
    if (!value.is_object()) return org;
    org.raw = value;
    org.id = string_or(value, "id");
    org.name = string_or(value, "name");
    org.roles = string_list(value, "roles");
    org.disabled = bool_or(value, "disabled");
    return org;
}

}  // namespace openback::app_auth
