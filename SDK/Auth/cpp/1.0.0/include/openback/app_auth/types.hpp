// openback-app-auth-cpp -- the data of a user pool: users, organizations, sign-in outcomes, tokens.
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace openback::app_auth {

/// A source of the current time (tests inject a fixed clock). Empty: std::chrono::system_clock::now.
using ClockFn = std::function<std::chrono::system_clock::time_point()>;

struct LinkedProvider {
    std::string provider_id;
    std::string kind;
};

/// A user of the pool (PoolUser). The fields of GET /me only (org_id, roles, providers, has_password) are empty in
/// the users returned by sign-in answers.
struct PoolUser {
    std::string id;                               // usr_...
    std::optional<std::string> email;             // null for guests
    bool email_verified = false;
    std::string display_name;
    std::optional<std::string> photo_url;
    std::optional<std::string> locale;            // "it" | "en" | null
    nlohmann::json attributes = nlohmann::json::object();
    bool anonymous = false;
    std::optional<std::string> created_at;
    std::optional<std::string> last_login_at;
    bool mfa_totp = false;                        // mfa.totp
    // GET /me only:
    std::optional<std::string> org_id;
    std::vector<std::string> roles;
    std::vector<LinkedProvider> providers;
    std::optional<bool> has_password;
    nlohmann::json raw = nlohmann::json::object();  // the user as the pool sent it

    static PoolUser from_json(const nlohmann::json& value);
};

/// The organization a session is in (B2B pools; null in B2C).
struct ActiveOrg {
    std::string id;
    std::string name;
    std::vector<std::string> roles;
    int choices = 0;                              // how many organizations the user may switch to
    nlohmann::json raw = nlohmann::json::object();

    static ActiveOrg from_json(const nlohmann::json& value);
};

enum class OutcomeStatus {
    Ok,                       // signed in: the Client keeps the session
    VerificationRequired,     // the email must be verified first (verify_email)
    MfaRequired,              // second factor: verify_mfa(mfa_token, code)
    MfaEnrollRequired,        // the pool requires a second factor: enroll_mfa(mfa_token) then confirm_mfa(code, mfa_token)
    PasswordChangeRequired,   // change_forced_password(change_token, new_password)
    Unknown                   // a status this version does not know (see status_name)
};

const char* to_string(OutcomeStatus status) noexcept;
OutcomeStatus outcome_status_from_string(std::string_view status) noexcept;

/// The answer of a sign-up / sign-in step. The tokens are never part of it: the Client keeps them (get_access_token).
struct Outcome {
    OutcomeStatus status = OutcomeStatus::Unknown;
    std::string status_name;                      // the raw "status"
    std::optional<PoolUser> user;
    std::optional<ActiveOrg> org;
    std::optional<std::string> mfa_token;         // MfaRequired, MfaEnrollRequired
    std::optional<std::string> change_token;      // PasswordChangeRequired
    std::vector<std::string> recovery_codes;      // confirm_mfa with an mfa_token
    nlohmann::json raw = nlohmann::json::object();  // the answer without access_token, refresh_token, id_token

    bool ok() const noexcept { return status == OutcomeStatus::Ok; }

    static Outcome from_json(const nlohmann::json& value);
};

/// Tokens from the token endpoint or a refresh.
struct TokenSet {
    std::string access_token;
    std::string token_type = "Bearer";
    std::int64_t expires_in = 0;                  // seconds
    std::string scope;
    std::string refresh_token;                    // rotated: always keep the newest one
    std::optional<std::int64_t> refresh_expires_in;
    std::optional<std::string> id_token;          // authorization code grant only
    std::optional<ActiveOrg> org;

    static TokenSet from_json(const nlohmann::json& value);
};

struct Organization {
    std::string id;
    std::string name;
    std::vector<std::string> roles;
    bool disabled = false;
    nlohmann::json raw = nlohmann::json::object();

    static Organization from_json(const nlohmann::json& value);
};

struct OrganizationList {
    std::vector<Organization> orgs;               // B2C pools: always empty
    std::optional<std::string> active;            // the session's organization
};

struct OrgRole {
    std::string key;
    std::string label;
};

struct Member {
    std::string user_id;
    std::optional<std::string> email;
    std::string display_name;
    bool disabled = false;
    std::vector<std::string> roles;
    std::optional<std::string> created_at;
    nlohmann::json raw = nlohmann::json::object();
};

struct MemberPage {
    std::vector<Member> items;
    std::optional<std::int64_t> total;
    std::vector<OrgRole> roles;                   // the roles of the pool (key, label)
};

struct MemberQuery {
    std::string q;
    int skip = 0;
    int limit = 50;
};

struct NewMember {
    std::string email;
    std::string display_name;
    std::optional<std::string> password;          // none: an unknown address gets a temporary password (in the answer)
    std::vector<std::string> roles;
};

struct MfaEnrollment {
    std::string secret;                           // TOTP secret: show it once, never log it
    std::string otpauth_uri;                      // for a QR code
};

struct MfaConfirmation {
    std::vector<std::string> recovery_codes;      // show them once
    std::optional<Outcome> outcome;               // confirmed with an mfa_token: the sign-in outcome
};

}  // namespace openback::app_auth
