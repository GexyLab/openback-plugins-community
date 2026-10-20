import io.openback.appauth.AppAuthClient;
import io.openback.appauth.AppAuthException;
import io.openback.appauth.AuthOutcome;
import io.openback.appauth.AuthorizationOptions;
import io.openback.appauth.LoopbackSignIn;
import io.openback.appauth.PoolUser;

import java.io.Console;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * A desktop/CLI app (pool app kind "native", redirect URI http://127.0.0.1:53682/callback registered exactly).
 *
 *   java -cp openback-app-auth-java-1.0.0.jar:jackson-*.jar DesktopSignIn.java hosted
 *   java -cp ... DesktopSignIn.java password
 */
public class DesktopSignIn {
    static final String ISSUER = "https://api.example.com/gateway/shop/auth/main";
    static final String CLIENT_ID = "uapp_your_native_app";

    public static void main(String[] args) throws Exception {
        AppAuthClient auth = AppAuthClient.builder(ISSUER, CLIENT_ID).build();
        auth.onAuthStateChanged((user, org) -> System.out.println(user == null ? "signed out" : "signed in as " + user.getId()));

        if (args.length > 0 && args[0].equals("password")) {
            Console console = System.console();
            String email = console.readLine("Email: ");
            String password = new String(console.readPassword("Password: "));
            try {
                AuthOutcome res = auth.signInWithPassword(email, password);
                switch (res.getStatus()) {
                    case MFA_REQUIRED:
                        res = auth.verifyMfa(res.getMfaToken(), console.readLine("Authenticator code: "));
                        break;
                    case PASSWORD_CHANGE_REQUIRED:
                        auth.changeForcedPassword(res.getChangeToken(), new String(console.readPassword("New password: ")));
                        System.out.println("Password changed: sign in again");
                        return;
                    case VERIFICATION_REQUIRED:
                        System.out.println("Check your inbox to verify the address first");
                        return;
                    default:
                        break;
                }
                System.out.println("status: " + res.getRawStatus());
            } catch (AppAuthException e) {
                System.out.println("Sign-in failed: " + e.getCode() + " - " + e.getMessage());   // never print tokens
                return;
            }
        } else {
            // hosted page in the system browser, back on the loopback address
            try (LoopbackSignIn loopback = LoopbackSignIn.start(53682, "/callback")) {
                PoolUser user = loopback.signIn(auth, new AuthorizationOptions().uiLocales("en"), Duration.ofMinutes(5));
                System.out.println("Hello " + user.getDisplayName());
            }
        }

        // call your API behind the OpenBack gateway (or your own backend verifying the token)
        HttpResponse<String> res = auth.send(HttpRequest.newBuilder(URI.create("https://api.example.com/gateway/shop/orders")),
                HttpResponse.BodyHandlers.ofString());
        System.out.println("orders: HTTP " + res.statusCode());

        auth.signOut();
    }
}
