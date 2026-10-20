# openback_app_auth_flutter example

Password sign-in (with the two-step verification, enrollment and forced password change branches), the pool's hosted
page, a call to your API with the access token, sign-out.

This folder holds only the Dart code and the web callback page. Generate the platform folders once, then apply the
platform setup of the package README (Android intent filter, iOS/macOS nothing extra, web `auth.html`):

```sh
cd example
flutter create --org com.example --project-name openback_app_auth_flutter_example --platforms=android,ios,macos,web,windows,linux .
flutter run \
  --dart-define=OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main \
  --dart-define=OPENBACK_CLIENT_ID=uapp_... \
  --dart-define=OPENBACK_API=https://api.example.com/gateway/shop/orders
```

Redirect addresses used (register them in the pool's app, also in its post-logout list for the hosted sign-out):

| Platform | App kind | Redirect address |
|---|---|---|
| iOS, macOS, Android | `native` | `com.example.app:/oauth2redirect` |
| Windows, Linux | `native` | `http://localhost:43823/callback` |
| Web | `spa` (allowed origin = the site's origin) | `<origin>/auth.html` |

Override with `--dart-define=OPENBACK_REDIRECT_URI=...`. On macOS enable the "Outgoing Connections (Client)"
entitlement (`com.apple.security.network.client`) for the network calls.
