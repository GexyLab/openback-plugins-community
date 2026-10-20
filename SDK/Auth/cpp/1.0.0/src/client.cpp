// openback-app-auth-cpp -- Client: the JSON API of a user pool, the session, single-flight refresh, hosted sign-in.
#include "openback/app_auth/client.hpp"

#include <condition_variable>
#include <cstdint>
#include <exception>
#include <map>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#include "openback/app_auth/jwt.hpp"
#include "internal.hpp"

namespace openback::app_auth {

namespace detail {

constexpr std::int64_t kRenewBeforeMs = 60000;  // renew the access token when it expires in 60 s or less
constexpr std::int64_t kDefaultExpiresIn = 900;

/// The session kept in the storage: {accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}.
struct ClientSession {
    std::string access_token;
    std::string refresh_token;
    std::string id_token;
    std::int64_t expires_at = 0;
    std::optional<PoolUser> user;
    std::optional<ActiveOrg> org;

    bool signed_in() const noexcept { return !refresh_token.empty(); }
};

/// One refresh request in flight; the threads that need a token meanwhile wait for its result.
struct RefreshFlight {
    bool done = false;
    std::string token;
    std::exception_ptr error;
};

namespace {

json session_to_json(const ClientSession& session) {
    json value = json::object();
    value["accessToken"] = session.access_token;
    value["refreshToken"] = session.refresh_token;
    value["idToken"] = session.id_token.empty() ? json(nullptr) : json(session.id_token);
    value["expiresAt"] = session.expires_at;
    value["user"] = session.user ? session.user->raw : json(nullptr);
    value["org"] = session.org ? session.org->raw : json(nullptr);
    return value;
}

std::optional<ClientSession> session_from_json(const std::string& text) {
    const json value = parse_json_or_null(text);
    if (!value.is_object()) return std::nullopt;
    ClientSession session;
    session.access_token = string_or(value, "accessToken");
    session.refresh_token = string_or(value, "refreshToken");
    session.id_token = string_or(value, "idToken");
    session.expires_at = opt_int(value, "expiresAt").value_or(0);
    const auto user = value.find("user");
    if (user != value.end() && user->is_object()) session.user = PoolUser::from_json(*user);
    const auto org = value.find("org");
    if (org != value.end() && org->is_object()) session.org = ActiveOrg::from_json(*org);
    if (!session.signed_in()) return std::nullopt;
    return session;
}

const json* object_member(const json& value, const char* key) {
    if (!value.is_object()) return nullptr;
    const auto it = value.find(key);
    if (it == value.end() || !it->is_object()) return nullptr;
    return &*it;
}

bool audience_matches(const json& claims, const std::string& client_id) {
    const auto aud = claims.find("aud");
    if (aud == claims.end()) return false;
    if (aud->is_string()) return aud->get<std::string>() == client_id;
    if (aud->is_array()) {
        for (const auto& item : *aud) {
            if (item.is_string() && item.get<std::string>() == client_id) return true;
        }
    }
    return false;
}

}  // namespace

}  // namespace detail

using detail::json;

struct Client::Impl {
    std::string issuer;
    std::string client_id;
    std::string api_base;
    std::string storage_key;
    ClientOptions options;
    std::shared_ptr<TokenStorage> storage;
    std::shared_ptr<HttpTransport> http;

    mutable std::mutex mutex;              // guards state and flight
    std::condition_variable flight_done;
    detail::ClientSession state;
    std::shared_ptr<detail::RefreshFlight> flight;

    std::mutex listeners_mutex;
    std::map<std::uint64_t, AuthStateListener> listeners;
    std::uint64_t next_listener = 1;

    Impl(std::string issuer_in, std::string client_id_in, ClientOptions options_in)
        : issuer(detail::strip_trailing_slashes(std::move(issuer_in))),
          client_id(std::move(client_id_in)),
          options(std::move(options_in)) {
        if (issuer.empty() || client_id.empty()) {
            throw std::invalid_argument("openback::app_auth::Client: issuer and client_id are required");
        }
        api_base = issuer + "/api/v1";
        storage_key = options.storage_key ? *options.storage_key : "openback.auth." + client_id;
        storage = options.storage ? options.storage : std::shared_ptr<TokenStorage>(std::make_shared<MemoryTokenStorage>());
        http = options.http ? options.http : default_transport();
        if (auto stored = load_stored()) state = std::move(*stored);
    }

    std::int64_t now_ms() const { return detail::to_epoch_ms(detail::now(options.clock)); }
    std::string pkce_key() const { return storage_key + ".pkce"; }

    // --- session ----------------------------------------------------------------------------------------------------

    std::optional<detail::ClientSession> load_stored() const {
        try {
            const std::optional<std::string> text = storage->get(storage_key);
            if (!text) return std::nullopt;
            return detail::session_from_json(*text);
        } catch (...) {
            return std::nullopt;
        }
    }

    // Called with `mutex` held.
    std::exception_ptr persist_locked() {
        try {
            if (state.signed_in()) {
                storage->set(storage_key, detail::session_to_json(state).dump());
            } else {
                storage->remove(storage_key);
            }
            return nullptr;
        } catch (...) {
            return std::current_exception();
        }
    }

    // Called WITHOUT `mutex` held: listeners may call the Client.
    void notify() {
        std::optional<PoolUser> user;
        std::optional<ActiveOrg> org;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (state.signed_in()) {
                user = state.user;
                org = state.org;
            }
        }
        std::vector<AuthStateListener> copy;
        {
            std::lock_guard<std::mutex> lock(listeners_mutex);
            copy.reserve(listeners.size());
            for (const auto& entry : listeners) copy.push_back(entry.second);
        }
        for (const auto& listener : copy) {
            try {
                listener(user, org);
            } catch (...) {
                // a listener's error is its own
            }
        }
    }

    // Replaces the session, stores it, tells the listeners; a storage error is rethrown afterwards.
    void commit(detail::ClientSession next) {
        std::exception_ptr storage_error;
        {
            std::lock_guard<std::mutex> lock(mutex);
            state = std::move(next);
            storage_error = persist_locked();
        }
        notify();
        if (storage_error) std::rethrow_exception(storage_error);
    }

    void clear_session() { commit(detail::ClientSession{}); }

    // A 401 for this access token: the session is dead (unless it was replaced meanwhile).
    void clear_if_access_token(const std::string& token) {
        bool cleared = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!token.empty() && state.access_token == token) {
                state = detail::ClientSession{};
                persist_locked();  // best effort: the in-memory session is gone anyway
                cleared = true;
            }
        }
        if (cleared) notify();
    }

    bool fresh_locked() const {
        return !state.access_token.empty() && state.expires_at - now_ms() > detail::kRenewBeforeMs;
    }

    detail::ClientSession session_from_tokens(const json& data, const detail::ClientSession& previous,
                                              bool keep_identity) const {
        detail::ClientSession next;
        next.access_token = detail::string_or(data, "access_token");
        next.refresh_token = detail::string_or(data, "refresh_token");
        if (next.refresh_token.empty() && keep_identity) next.refresh_token = previous.refresh_token;
        const std::optional<std::string> id_token = detail::opt_string(data, "id_token");
        next.id_token = id_token ? *id_token : (keep_identity ? previous.id_token : std::string());
        next.expires_at = now_ms() + detail::opt_int(data, "expires_in").value_or(detail::kDefaultExpiresIn) * 1000;
        if (const json* user = detail::object_member(data, "user")) {
            next.user = PoolUser::from_json(*user);
        } else if (keep_identity) {
            next.user = previous.user;
        }
        if (const json* org = detail::object_member(data, "org")) next.org = ActiveOrg::from_json(*org);
        return next;
    }

    void update_user(const PoolUser& user) {
        bool changed = false;
        std::exception_ptr storage_error;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (state.signed_in() && (!state.user || state.user->id == user.id)) {
                state.user = user;
                storage_error = persist_locked();
                changed = true;
            }
        }
        if (changed) notify();
        if (storage_error) std::rethrow_exception(storage_error);
    }

    void update_user_from(const json& data) {
        if (const json* user = detail::object_member(data, "user")) update_user(PoolUser::from_json(*user));
    }

    // --- HTTP -------------------------------------------------------------------------------------------------------

    json call(const std::string& method, const std::string& path, const json* body,
              const std::optional<std::string>& bearer) {
        HttpRequest request;
        request.method = method;
        request.url = api_base + path;
        request.timeout = options.timeout;
        request.headers.emplace_back("X-Client-Id", client_id);
        request.headers.emplace_back("Accept", "application/json");
        if (body) {
            request.headers.emplace_back("Content-Type", "application/json");
            try {
                request.body = body->dump();
            } catch (const json::exception&) {
                throw AppAuthError(400, "invalid_utf8", "A text field is not valid UTF-8");
            }
        }
        if (bearer) request.headers.emplace_back("Authorization", "Bearer " + *bearer);
        const HttpResponse response = detail::send_checked(*http, request);
        if (!response.ok()) {
            AppAuthError error = detail::error_from_response(response);
            if (bearer && response.status == 401 &&
                (detail::starts_with(error.code(), "token_") || error.code() == "invalid_refresh_token")) {
                clear_if_access_token(*bearer);
            }
            throw error;
        }
        return detail::parse_json_or_null(response.body);
    }

    json authed(const std::string& method, const std::string& path, const json* body) {
        const std::string token = get_access_token();
        return call(method, path, body, token);
    }

    Outcome outcome(const json& data) {
        Outcome out = Outcome::from_json(data);
        if (out.ok() && detail::opt_string(data, "access_token")) {
            commit(session_from_tokens(data, detail::ClientSession{}, false));
        }
        return out;
    }

    // --- tokens -----------------------------------------------------------------------------------------------------

    std::string get_access_token() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (fresh_locked()) return state.access_token;
        }
        return rotate(std::nullopt, false, std::string());
    }

    // Uses the refresh token (POST /token/refresh, or /orgs/switch when switching): one request at a time, the new
    // refresh token stored before anyone else may use it. Never retried automatically.
    std::string rotate(const std::optional<std::string>& org_id, bool switching, const std::string& bearer) {
        std::unique_lock<std::mutex> lock(mutex);
        const bool plain = !switching && !org_id;
        while (flight) {
            const std::shared_ptr<detail::RefreshFlight> current = flight;
            flight_done.wait(lock, [&current] { return current->done; });
            if (plain) {
                if (current->error) std::rethrow_exception(current->error);
                return current->token;
            }
        }
        // Another process sharing the storage may have rotated the tokens already: use its refresh token.
        if (std::optional<detail::ClientSession> stored = load_stored();
            stored && stored->refresh_token != state.refresh_token) {
            state = std::move(*stored);
            if (plain && fresh_locked()) return state.access_token;
        }
        if (!state.signed_in()) throw AppAuthError(401, "not_signed_in", "Not signed in");

        const auto current = std::make_shared<detail::RefreshFlight>();
        flight = current;
        const std::string refresh_token = state.refresh_token;
        lock.unlock();

        json data;
        std::exception_ptr error;
        bool dead = false;
        try {
            if (switching) {
                json body = json::object();
                body["org_id"] = org_id.value_or(std::string());
                body["refresh_token"] = refresh_token;
                data = call("POST", "/orgs/switch", &body, bearer);
            } else {
                json body = json::object();
                body["refresh_token"] = refresh_token;
                if (org_id) body["org_id"] = *org_id;
                data = call("POST", "/token/refresh", &body, std::nullopt);
            }
        } catch (const AppAuthError& e) {
            // 401: the refresh token is refused. A 403 not_a_member on a switch leaves it valid (the pool checks the
            // membership before using it).
            dead = e.status() == 401;
            error = std::current_exception();
        } catch (...) {
            error = std::current_exception();
        }

        std::string token;
        bool changed = false;
        std::exception_ptr storage_error;
        lock.lock();
        if (!error) {
            if (state.refresh_token == refresh_token) {
                state = session_from_tokens(data, state, true);
                storage_error = persist_locked();
                changed = true;
                token = state.access_token;
            } else if (state.signed_in()) {
                token = state.access_token;  // a new sign-in happened meanwhile: its token
            } else {
                error = std::make_exception_ptr(AppAuthError(401, "not_signed_in", "Signed out during the refresh"));
            }
        } else if (dead && state.refresh_token == refresh_token) {
            state = detail::ClientSession{};
            storage_error = persist_locked();
            changed = true;
        }
        current->done = true;
        current->token = token;
        current->error = error;
        flight.reset();
        lock.unlock();
        flight_done.notify_all();

        if (changed) notify();
        if (error) std::rethrow_exception(error);
        if (storage_error) std::rethrow_exception(storage_error);
        return token;
    }
};

// --- construction --------------------------------------------------------------------------------------------------

Client::Client(std::string issuer, std::string client_id, ClientOptions options)
    : impl_(std::make_shared<Impl>(std::move(issuer), std::move(client_id), std::move(options))) {}

Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

const std::string& Client::issuer() const noexcept { return impl_->issuer; }
const std::string& Client::client_id() const noexcept { return impl_->client_id; }

json Client::config() { return impl_->call("GET", "/config", nullptr, std::nullopt); }

// --- state ---------------------------------------------------------------------------------------------------------

std::optional<PoolUser> Client::current_user() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->state.signed_in()) return std::nullopt;
    return impl_->state.user;
}

std::optional<ActiveOrg> Client::current_org() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->state.signed_in()) return std::nullopt;
    return impl_->state.org;
}

std::optional<json> Client::access_token_claims() const {
    std::string token;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        token = impl_->state.access_token;
    }
    if (token.empty()) return std::nullopt;
    return decode_jwt_payload(token);
}

bool Client::is_signed_in() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->state.signed_in();
}

std::function<void()> Client::on_auth_state_changed(AuthStateListener listener) {
    if (!listener) return [] {};
    std::uint64_t id = 0;
    {
        std::lock_guard<std::mutex> lock(impl_->listeners_mutex);
        id = impl_->next_listener++;
        impl_->listeners.emplace(id, listener);
    }
    std::optional<PoolUser> user;
    std::optional<ActiveOrg> org;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->state.signed_in()) {
            user = impl_->state.user;
            org = impl_->state.org;
        }
    }
    try {
        listener(user, org);
    } catch (...) {
        // a listener's error is its own
    }
    std::weak_ptr<Impl> weak = impl_;
    return [weak, id] {
        if (const auto impl = weak.lock()) {
            std::lock_guard<std::mutex> lock(impl->listeners_mutex);
            impl->listeners.erase(id);
        }
    };
}

// --- tokens --------------------------------------------------------------------------------------------------------

std::string Client::get_access_token() { return impl_->get_access_token(); }

std::string Client::refresh(const std::optional<std::string>& org_id) {
    return impl_->rotate(org_id, false, std::string());
}

HttpResponse Client::authorized_request(HttpRequest request) {
    request.set_header("Authorization", "Bearer " + impl_->get_access_token());
    return detail::send_checked(*impl_->http, request);
}

// --- sign-up and sign-in -------------------------------------------------------------------------------------------

Outcome Client::sign_up(const SignUpParams& params) {
    json body = json::object();
    body["email"] = params.email;
    body["password"] = params.password;
    body["display_name"] = params.display_name;
    if (params.locale) body["locale"] = *params.locale;
    if (params.org_id) body["org_id"] = *params.org_id;
    return impl_->outcome(impl_->call("POST", "/signup", &body, std::nullopt));
}

Outcome Client::sign_in_with_password(const std::string& email, const std::string& password,
                                      const std::optional<std::string>& org_id) {
    json body = json::object();
    body["email"] = email;
    body["password"] = password;
    if (org_id) body["org_id"] = *org_id;
    return impl_->outcome(impl_->call("POST", "/signin/password", &body, std::nullopt));
}

json Client::send_email_code(const std::string& email) {
    json body = json::object();
    body["email"] = email;
    return impl_->call("POST", "/signin/email-code", &body, std::nullopt);
}

Outcome Client::sign_in_with_email_code(const EmailCodeParams& params) {
    json body = json::object();
    if (params.email) body["email"] = *params.email;
    if (params.code) body["code"] = *params.code;
    if (params.token) body["token"] = *params.token;
    if (params.org_id) body["org_id"] = *params.org_id;
    return impl_->outcome(impl_->call("POST", "/signin/email-code/verify", &body, std::nullopt));
}

Outcome Client::sign_in_anonymously() {
    return impl_->outcome(impl_->call("POST", "/signin/anonymous", nullptr, std::nullopt));
}

Outcome Client::verify_mfa(const std::string& mfa_token, const std::string& code) {
    json body = json::object();
    body["mfa_token"] = mfa_token;
    body["code"] = code;
    return impl_->outcome(impl_->call("POST", "/signin/mfa", &body, std::nullopt));
}

MfaEnrollment Client::enroll_mfa(const std::optional<std::string>& mfa_token) {
    json data;
    if (mfa_token) {
        json body = json::object();
        body["mfa_token"] = *mfa_token;
        data = impl_->call("POST", "/mfa/enroll", &body, std::nullopt);
    } else {
        const json empty = json::object();
        data = impl_->authed("POST", "/mfa/enroll", &empty);
    }
    return MfaEnrollment{detail::string_or(data, "secret"), detail::string_or(data, "otpauth_uri")};
}

MfaConfirmation Client::confirm_mfa(const std::string& code, const std::optional<std::string>& mfa_token) {
    json body = json::object();
    body["code"] = code;
    MfaConfirmation result;
    if (mfa_token) {
        body["mfa_token"] = *mfa_token;
        const json data = impl_->call("POST", "/mfa/enroll/confirm", &body, std::nullopt);
        result.recovery_codes = detail::string_list(data, "recovery_codes");
        result.outcome = impl_->outcome(data);
    } else {
        const json data = impl_->authed("POST", "/mfa/enroll/confirm", &body);
        result.recovery_codes = detail::string_list(data, "recovery_codes");
    }
    return result;
}

json Client::disable_mfa(const std::string& code) {
    json body = json::object();
    body["code"] = code;
    return impl_->authed("POST", "/mfa/disable", &body);
}

// --- passwords and emails ------------------------------------------------------------------------------------------

json Client::send_password_reset(const std::string& email) {
    json body = json::object();
    body["email"] = email;
    return impl_->call("POST", "/password/forgot", &body, std::nullopt);
}

json Client::reset_password(const ResetPasswordParams& params) {
    json body = json::object();
    if (params.token) body["token"] = *params.token;
    if (params.email) body["email"] = *params.email;
    if (params.code) body["code"] = *params.code;
    body["new_password"] = params.new_password;
    return impl_->call("POST", "/password/reset", &body, std::nullopt);
}

json Client::change_forced_password(const std::string& change_token, const std::string& new_password) {
    json body = json::object();
    body["change_token"] = change_token;
    body["new_password"] = new_password;
    return impl_->call("POST", "/password/reset", &body, std::nullopt);
}

json Client::verify_email(const VerifyEmailParams& params) {
    json body = json::object();
    if (params.token) body["token"] = *params.token;
    if (params.email) body["email"] = *params.email;
    if (params.code) body["code"] = *params.code;
    json data = impl_->call("POST", "/email/verify", &body, std::nullopt);
    impl_->update_user_from(data);
    return data;
}

json Client::resend_verification() {
    const json empty = json::object();
    return impl_->authed("POST", "/email/verify/send", &empty);
}

// --- the signed-in user --------------------------------------------------------------------------------------------

PoolUser Client::me() {
    PoolUser user = PoolUser::from_json(impl_->authed("GET", "/me", nullptr));
    impl_->update_user(user);
    return user;
}

PoolUser Client::update_profile(const ProfileUpdate& update) {
    json body = json::object();
    if (update.display_name) body["display_name"] = *update.display_name;
    if (update.photo_url) body["photo_url"] = *update.photo_url;
    if (update.locale) body["locale"] = *update.locale;
    PoolUser user = PoolUser::from_json(impl_->authed("PATCH", "/me", &body));
    impl_->update_user(user);
    return user;
}

json Client::change_password(const std::optional<std::string>& current_password, const std::string& new_password) {
    json body = json::object();
    if (current_password) body["current_password"] = *current_password;
    body["new_password"] = new_password;
    json data = impl_->authed("POST", "/me/password", &body);
    impl_->clear_session();  // every session ends: sign in again
    return data;
}

json Client::change_email(const std::string& new_email) {
    json body = json::object();
    body["new_email"] = new_email;
    return impl_->authed("POST", "/me/email", &body);
}

json Client::confirm_email_change(const EmailChangeConfirmation& confirmation) {
    json body = json::object();
    if (confirmation.code) body["code"] = *confirmation.code;
    if (confirmation.token) body["token"] = *confirmation.token;
    json data = impl_->authed("POST", "/me/email/confirm", &body);
    impl_->update_user_from(data);
    return data;
}

json Client::upgrade_anonymous(const std::string& email, const std::string& password) {
    json body = json::object();
    body["email"] = email;
    body["password"] = password;
    json data = impl_->authed("POST", "/me/upgrade", &body);
    impl_->update_user_from(data);
    return data;
}

json Client::delete_account(const std::optional<std::string>& password) {
    json body = json::object();
    if (password) body["password"] = *password;
    json data = impl_->authed("DELETE", "/me", &body);
    impl_->clear_session();
    return data;
}

void Client::sign_out(bool everywhere) {
    detail::ClientSession snapshot;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        snapshot = impl_->state;
    }
    if (snapshot.signed_in()) {
        try {
            std::optional<std::string> bearer;
            if (!snapshot.access_token.empty() && snapshot.expires_at - impl_->now_ms() > 5000) {
                bearer = snapshot.access_token;
            } else if (everywhere) {
                // "everywhere" needs the user: renew the access token first (best effort).
                try {
                    bearer = impl_->get_access_token();
                    std::lock_guard<std::mutex> lock(impl_->mutex);
                    snapshot = impl_->state;
                } catch (...) {
                    bearer.reset();
                }
            }
            if (snapshot.signed_in()) {
                json body = json::object();
                body["refresh_token"] = snapshot.refresh_token;
                body["everywhere"] = everywhere;
                impl_->call("POST", "/signout", &body, bearer);
            }
        } catch (...) {
            // signed out locally anyway
        }
    }
    try {
        impl_->clear_session();
    } catch (...) {
        // a storage that cannot remove the key: the in-memory session is cleared anyway
    }
}

// --- organizations -------------------------------------------------------------------------------------------------

OrganizationList Client::organizations() {
    const json data = impl_->authed("GET", "/orgs", nullptr);
    OrganizationList list;
    const auto orgs = data.is_object() ? data.find("orgs") : data.end();
    if (data.is_object() && orgs != data.end() && orgs->is_array()) {
        for (const auto& item : *orgs) list.orgs.push_back(Organization::from_json(item));
    }
    list.active = detail::opt_string(data, "active");
    return list;
}

Organization Client::create_organization(const std::string& name) {
    json body = json::object();
    body["name"] = name;
    return Organization::from_json(impl_->authed("POST", "/orgs", &body));
}

std::optional<ActiveOrg> Client::switch_organization(const std::string& org_id) {
    const std::string bearer = impl_->get_access_token();
    impl_->rotate(org_id, true, bearer);
    return current_org();
}

MemberPage Client::members(const std::string& org_id, const MemberQuery& query) {
    const std::string path = "/orgs/" + detail::url_encode(org_id) + "/members?q=" + detail::url_encode(query.q) +
                             "&skip=" + std::to_string(query.skip) + "&limit=" + std::to_string(query.limit);
    const json data = impl_->authed("GET", path, nullptr);
    MemberPage page;
    if (!data.is_object()) return page;
    const auto items = data.find("items");
    if (items != data.end() && items->is_array()) {
        for (const auto& item : *items) {
            if (!item.is_object()) continue;
            Member member;
            member.raw = item;
            member.user_id = detail::string_or(item, "user_id");
            member.email = detail::opt_string(item, "email");
            member.display_name = detail::string_or(item, "display_name");
            member.disabled = detail::bool_or(item, "disabled");
            member.roles = detail::string_list(item, "roles");
            member.created_at = detail::opt_string(item, "created_at");
            page.items.push_back(std::move(member));
        }
    }
    page.total = detail::opt_int(data, "total");
    const auto roles = data.find("roles");
    if (roles != data.end() && roles->is_array()) {
        for (const auto& role : *roles) {
            if (role.is_object()) page.roles.push_back(OrgRole{detail::string_or(role, "key"), detail::string_or(role, "label")});
        }
    }
    return page;
}

json Client::add_member(const std::string& org_id, const NewMember& member) {
    json body = json::object();
    body["email"] = member.email;
    body["display_name"] = member.display_name;
    if (member.password) body["password"] = *member.password;
    body["roles"] = member.roles;
    return impl_->authed("POST", "/orgs/" + detail::url_encode(org_id) + "/members", &body);
}

json Client::set_member_roles(const std::string& org_id, const std::string& user_id,
                              const std::vector<std::string>& roles) {
    json body = json::object();
    body["roles"] = roles;
    return impl_->authed("PATCH", "/orgs/" + detail::url_encode(org_id) + "/members/" + detail::url_encode(user_id), &body);
}

json Client::remove_member(const std::string& org_id, const std::string& user_id) {
    return impl_->authed("DELETE", "/orgs/" + detail::url_encode(org_id) + "/members/" + detail::url_encode(user_id),
                         nullptr);
}

// --- hosted sign-in ------------------------------------------------------------------------------------------------

AuthorizationRequest Client::build_authorization_request(const AuthorizationOptions& options) {
    const std::string redirect = options.redirect_uri ? *options.redirect_uri : impl_->options.redirect_uri.value_or("");
    AuthorizationRequest request =
        ::openback::app_auth::build_authorization_request(impl_->issuer, impl_->client_id, redirect, options);
    impl_->storage->set(impl_->pkce_key(), request.to_json().dump());
    return request;
}

std::optional<PoolUser> Client::handle_redirect_callback(const std::string& callback_url) {
    const CallbackParams params = CallbackParams::from_url(callback_url);
    if (!params.is_callback()) throw AppAuthError(400, "invalid_request", "The URL is not a sign-in callback");

    AuthorizationRequest pending;
    bool has_pending = false;
    if (const std::optional<std::string> text = impl_->storage->get(impl_->pkce_key())) {
        const json value = detail::parse_json_or_null(*text);
        if (value.is_object()) {
            pending = AuthorizationRequest::from_json(value);
            has_pending = true;
        }
    }
    if (params.error) impl_->storage->remove(impl_->pkce_key());
    if (!has_pending && !params.error) throw AppAuthError(400, "invalid_state", "No sign-in in progress");
    const std::string code = validate_callback(params, pending, impl_->issuer);
    impl_->storage->remove(impl_->pkce_key());  // one use

    detail::ClientCredentials credentials{impl_->client_id, impl_->options.client_secret,
                                          impl_->options.client_secret_basic};
    detail::FormFields form;
    form.emplace_back("grant_type", "authorization_code");
    form.emplace_back("code", code);
    form.emplace_back("redirect_uri", pending.redirect_uri);
    form.emplace_back("code_verifier", pending.code_verifier);
    const json data =
        detail::post_form(*impl_->http, impl_->issuer + "/token", std::move(form), credentials, impl_->options.timeout);

    if (const std::optional<std::string> id_token = detail::opt_string(data, "id_token")) {
        // The ID token comes straight from the token endpoint over TLS (OIDC Core 3.1.3.7): its claims are checked
        // here; use TokenVerifier::verify_id_token to check its signature as well.
        const std::optional<json> claims = decode_jwt_payload(*id_token);
        if (!claims) throw AppAuthError(400, "invalid_id_token", "The ID token cannot be read");
        const std::optional<std::string> nonce = detail::opt_string(*claims, "nonce");
        if (!nonce || pending.nonce.empty() || !detail::constant_time_equals(*nonce, pending.nonce)) {
            throw AppAuthError(400, "invalid_nonce", "Nonce mismatch");
        }
        if (detail::opt_string(*claims, "iss") != impl_->issuer) {
            throw AppAuthError(400, "invalid_id_token", "The ID token has another issuer");
        }
        if (!detail::audience_matches(*claims, impl_->client_id)) {
            throw AppAuthError(400, "invalid_id_token", "The ID token is for another app");
        }
    }
    if (!detail::opt_string(data, "access_token")) {
        throw AppAuthError(502, "invalid_response", "The token endpoint answered without an access token");
    }
    impl_->commit(impl_->session_from_tokens(data, detail::ClientSession{}, false));
    try {
        return me();
    } catch (const AppAuthError&) {
        return std::nullopt;  // signed in; the profile can be loaded later with me()
    }
}

std::string Client::build_logout_url(const std::optional<std::string>& post_logout_redirect_uri,
                                     const std::optional<std::string>& state) const {
    LogoutOptions options;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->state.id_token.empty()) options.id_token_hint = impl_->state.id_token;
    }
    options.post_logout_redirect_uri = post_logout_redirect_uri;
    options.state = state;
    return ::openback::app_auth::build_logout_url(impl_->issuer, impl_->client_id, options);
}

std::string Client::sign_out_redirect(const std::optional<std::string>& post_logout_redirect_uri,
                                      const std::optional<std::string>& state) {
    std::string url = build_logout_url(post_logout_redirect_uri, state);
    sign_out(false);
    return url;
}

}  // namespace openback::app_auth
