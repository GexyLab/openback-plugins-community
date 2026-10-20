// Verifying the pool's access tokens in your own server: a framework-neutral request handler built on BearerGuard.
//
//   verify_token_server <issuer> <client id> "<Authorization header value>"
//   verify_token_server https://api.example.com/gateway/shop/auth/main uapp_123 "Bearer eyJ..."
//
// prints the HTTP response your server would send. With a real HTTP library, call handle() from its route; e.g. with
// cpp-httplib (https://github.com/yhirose/cpp-httplib):
//
//   httplib::Server server;
//   server.Get("/orders", [&](const httplib::Request& req, httplib::Response& res) {
//       const Response out = handle(guard, req.get_header_value("Authorization"));
//       res.status = out.status;
//       for (const auto& [name, value] : out.headers) res.set_header(name, value);
//       res.set_content(out.body, "application/json");
//   });
//   server.listen("0.0.0.0", 8080);
//
// The verification is local (the pool's public keys are fetched once and cached); a signed-out user's access token
// stays valid until it expires (default 15 minutes).
#include <iostream>
#include <string>

#include <openback/app_auth.hpp>

namespace auth = openback::app_auth;

namespace {

struct Response {
    int status = 200;
    auth::HttpHeaders headers;
    std::string body;
};

// GET /orders: only signed-in members with the permission "orders.read".
Response handle(const auth::BearerGuard& guard, const std::string& authorization_header) {
    const auth::GuardResult check = guard.check(authorization_header);
    if (!check) return Response{check.status, check.headers, check.body};  // 401 / 403 / 503, body {"error": ...}

    const auth::AppUser& user = *check.user;
    nlohmann::json body = {{"user", user.id},
                           {"organization", user.org_id ? nlohmann::json(*user.org_id) : nlohmann::json(nullptr)},
                           {"admin", user.has_role("admin")},
                           {"orders", nlohmann::json::array()}};
    return Response{200, {{"Content-Type", "application/json"}}, body.dump()};
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: verify_token_server <issuer> <client id> \"Bearer <access token>\"\n";
        return 2;
    }
    try {
        auth::VerifierOptions options;
        options.audiences = {argv[2]};  // the client IDs whose tokens this server accepts
        auth::TokenVerifier verifier(argv[1], options);

        auth::GuardOptions requirements;
        requirements.require_permissions = {"orders.read"};
        requirements.require_verified_email = true;
        const auth::BearerGuard guard(verifier, requirements);

        const Response response = handle(guard, argv[3]);
        std::cout << "HTTP " << response.status << "\n";
        for (const auto& [name, value] : response.headers) std::cout << name << ": " << value << "\n";
        std::cout << "\n" << response.body << "\n";
        return response.status == 200 ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
