// Console sign-in with email and password, including the two-step verification branches.
//
//   password_sign_in <issuer> <client id> [your API URL]
//   password_sign_in https://api.example.com/gateway/shop/auth/main uapp_123 https://api.example.com/gateway/shop/orders
//
// Register a "native" app in the pool (Apps tab) and use its client ID. The tokens are never printed.
// Note: this example reads the password with echo on, to stay portable; a real CLI should disable the echo
// (termios on POSIX, SetConsoleMode on Windows).
#include <iostream>
#include <string>

#include <openback/app_auth.hpp>

namespace auth = openback::app_auth;

namespace {

std::string ask(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

// Continues a sign-in until it is "ok" or cannot go on here.
auth::Outcome complete(auth::Client& client, auth::Outcome outcome) {
    for (;;) {
        switch (outcome.status) {
            case auth::OutcomeStatus::Ok:
                return outcome;
            case auth::OutcomeStatus::MfaRequired:
                outcome = client.verify_mfa(*outcome.mfa_token, ask("Authenticator code (or a recovery code): "));
                break;
            case auth::OutcomeStatus::MfaEnrollRequired: {
                const std::string mfa_token = *outcome.mfa_token;
                const auth::MfaEnrollment enrollment = client.enroll_mfa(mfa_token);
                std::cout << "Two-step verification is required. Add this account to your authenticator app:\n  "
                          << enrollment.otpauth_uri << "\n";
                const auth::MfaConfirmation confirmation = client.confirm_mfa(ask("Code from the app: "), mfa_token);
                std::cout << "Keep these recovery codes somewhere safe:\n";
                for (const auto& code : confirmation.recovery_codes) std::cout << "  " << code << "\n";
                if (!confirmation.outcome) return outcome;
                outcome = *confirmation.outcome;
                break;
            }
            case auth::OutcomeStatus::PasswordChangeRequired:
                client.change_forced_password(*outcome.change_token, ask("You must choose a new password: "));
                std::cout << "Password changed: sign in again with the new one.\n";
                return outcome;
            case auth::OutcomeStatus::VerificationRequired:
                std::cout << "Check your inbox: the email address must be verified first.\n";
                return outcome;
            case auth::OutcomeStatus::Unknown:
                std::cout << "Unexpected answer: " << outcome.status_name << "\n";
                return outcome;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: password_sign_in <issuer> <client id> [api url]\n";
        return 2;
    }
    try {
        auth::Client client(argv[1], argv[2]);
        auto unsubscribe = client.on_auth_state_changed(
            [](const std::optional<auth::PoolUser>& user, const std::optional<auth::ActiveOrg>& org) {
                if (user) {
                    std::cout << "[state] signed in as " << user->email.value_or(user->id)
                              << (org ? " in " + org->name : std::string()) << "\n";
                } else {
                    std::cout << "[state] signed out\n";
                }
            });

        const std::string email = ask("Email: ");
        const std::string password = ask("Password: ");
        const auth::Outcome outcome = complete(client, client.sign_in_with_password(email, password));
        if (!outcome.ok()) return 1;

        const auth::PoolUser me = client.me();
        std::cout << "Hello " << (me.display_name.empty() ? me.id : me.display_name) << " ("
                  << (me.email_verified ? "verified" : "not verified") << ")\n";

        if (argc > 3) {
            // Your API behind the OpenBack gateway (endpoint check "Authenticated app user") or your own server.
            auth::HttpRequest request;
            request.method = "GET";
            request.url = argv[3];
            request.headers.emplace_back("Accept", "application/json");
            const auth::HttpResponse response = client.authorized_request(request);
            std::cout << "GET " << argv[3] << " -> " << response.status << "\n" << response.body << "\n";
        }

        client.sign_out();
        unsubscribe();
        return 0;
    } catch (const auth::AppAuthError& e) {
        std::cerr << "error " << e.status() << " " << e.code() << ": " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
