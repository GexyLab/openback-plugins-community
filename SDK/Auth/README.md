# OpenBack App Auth SDKs

Client libraries and plugins for OpenBack's **App authenticator** (users-service): they sign the users of your apps in
to an OpenBack **user pool** — sign-up, password, email code, guest accounts, two-step verification, social providers
through the pool's hosted page (OpenID Connect), organizations (B2B) — and let your servers verify the pool's tokens.

Every package is named `openback-app-auth-<platform>`. Each version lives in its own directory
(`<platform>/<version>/`) holding the complete package: sources, tests, examples, `README.md`, `CHANGELOG.md`,
`LICENSE`. A published version directory never changes: a new version is a new directory.

| Platform | Directory | Package | For | License |
|---|---|---|---|---|
| JavaScript (browser) | [javascript/1.0.0](javascript/1.0.0) | `openback-app-auth-javascript` (npm) | web apps, plain `<script>` or bundlers | MIT |
| Node.js | [nodejs/1.0.0](nodejs/1.0.0) | `openback-app-auth-nodejs` (npm) | servers: token verification, Express/Fastify, OIDC web login | MIT |
| Python | [python/1.0.0](python/1.0.0) | `openback-app-auth-python` (PyPI) | apps and servers: FastAPI, Flask, Django | MIT |
| PHP | [php/1.0.0](php/1.0.0) | `openback/openback-app-auth-php` (Composer) | servers, PSR-15 middleware | MIT |
| C# / .NET | [csharp/1.0.0](csharp/1.0.0) | `openback-app-auth-csharp`, `-aspnetcore` (NuGet) | desktop, MAUI, Unity, ASP.NET Core | MIT |
| Java | [java/1.0.0](java/1.0.0) | `io.openback:openback-app-auth-java`, `-spring-boot-starter` (Maven) | servers, desktop, Spring Boot | MIT |
| C++ | [cpp/1.0.0](cpp/1.0.0) | `openback-app-auth-cpp` (CMake, vcpkg, Conan) | native desktop, embedded, servers | MIT |
| Flutter | [flutter/1.0.0](flutter/1.0.0) | `openback_app_auth_flutter` (pub.dev) | iOS, Android, web, desktop | MIT |
| iOS / macOS (Swift) | [ios/1.0.0](ios/1.0.0) | `openback-app-auth-ios` (SwiftPM, CocoaPods) | native Apple apps | MIT |
| Android (Kotlin) | [android/1.0.0](android/1.0.0) | `io.openback:openback-app-auth-android` (Maven) | native Android apps | MIT |
| WordPress | [wordpress/1.0.0](wordpress/1.0.0) | `openback-app-auth-wordpress` (plugin) | sign-in to WordPress sites | GPL-2.0-or-later |
| Joomla | [joomla/1.0.0](joomla/1.0.0) | `pkg_openbackappauth` (package) | sign-in to Joomla 4/5 sites | GPL-2.0-or-later |
| Shopify Plus | [shopify/1.0.0](shopify/1.0.0) | `openback-app-auth-shopify` (guide + npm helper) | OpenBack as the identity provider of Shopify customer accounts | MIT |

## Before you start

1. In the OpenBack portal, open the user pool and register your app in its **Apps** tab. Pick the kind that matches:
   `spa` (browser app: list its origins), `web` (web app with a server: client secret + redirect address),
   `native` (mobile/desktop: custom-scheme or https redirect address), `backend` (a server).
2. Note the pool's address (the **issuer**, e.g. `https://api.example.com/gateway/shop/auth/main`) and the app's
   **client ID** (`uapp_...`). Every SDK starts from these two values.

The service's full reference (JSON API, tokens, OpenID Connect endpoints) is in each package's README and in OpenBack's
developer documentation (`doc/dev/users-service`).

## Packages are not published yet

The registry names above are the planned ones; until a package is published, install it from its directory (every
README explains how).
