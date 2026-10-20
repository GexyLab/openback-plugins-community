// Console sign-in to an OpenBack user pool: password + two-step verification, or the hosted page in the system browser.
//
//   set OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main
//   set OPENBACK_CLIENT_ID=uapp_...
//   dotnet run                       # email + password (+ MFA code)
//   set OPENBACK_REDIRECT_URI=http://127.0.0.1:53682/callback
//   dotnet run -- --browser          # hosted page (register the loopback URI in the pool's Apps tab, kind "native")
//   set OPENBACK_API_URL=https://api.example.com/gateway/shop/orders
//                                    # optional: an API of yours called with the access token
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using OpenBack.AppAuth;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var issuer = Environment.GetEnvironmentVariable("OPENBACK_ISSUER");
        var clientId = Environment.GetEnvironmentVariable("OPENBACK_CLIENT_ID");
        if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(clientId))
        {
            Console.Error.WriteLine("Set OPENBACK_ISSUER and OPENBACK_CLIENT_ID.");
            return 2;
        }

        var options = new AppAuthClientOptions { RedirectUri = Environment.GetEnvironmentVariable("OPENBACK_REDIRECT_URI") };
        if (OperatingSystem.IsWindows()) options.Storage = new ProtectedFileTokenStorage();   // DPAPI, current Windows user

        using var auth = await AppAuthClient.CreateAsync(issuer, clientId, options);
        auth.OnAuthStateChanged((user, org) =>
            Console.WriteLine(user == null ? "[state] signed out" : $"[state] signed in as {user.Email ?? user.Id}"));

        try
        {
            if (!auth.IsSignedIn)
            {
                if (Array.IndexOf(args, "--browser") >= 0)
                {
                    Console.WriteLine("Opening the sign-in page in your browser...");
                    await auth.SignInWithSystemBrowserAsync();
                }
                else if (!await SignInWithPasswordAsync(auth))
                {
                    return 1;
                }
            }

            var me = await auth.MeAsync();
            Console.WriteLine($"Hello {me.DisplayName ?? me.Email}! (roles: {string.Join(", ", me.Roles ?? new())})");

            var apiUrl = Environment.GetEnvironmentVariable("OPENBACK_API_URL");
            if (!string.IsNullOrEmpty(apiUrl))
            {
                using var api = auth.CreateAuthorizedHttpClient();   // adds Authorization: Bearer <access token>
                var res = await api.GetAsync(apiUrl);
                Console.WriteLine($"GET {apiUrl} -> {(int)res.StatusCode}");
            }

            Console.Write("Sign out? [y/N] ");
            if ((Console.ReadLine() ?? "").Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
                await auth.SignOutAsync();
            return 0;
        }
        catch (AppAuthException e)
        {
            // Never print tokens; the code and message are safe.
            Console.Error.WriteLine($"Error {e.Status} {e.Code}: {e.Message}");
            return 1;
        }
    }

    private static async Task<bool> SignInWithPasswordAsync(AppAuthClient auth)
    {
        Console.Write("Email: ");
        var email = Console.ReadLine() ?? "";
        Console.Write("Password: ");
        var password = ReadSecret();

        var outcome = await auth.SignInWithPasswordAsync(email, password);
        while (true)
        {
            switch (outcome.Status)
            {
                case AuthStatus.Ok:
                    return true;
                case AuthStatus.MfaRequired:
                    Console.Write("Authenticator code (or a recovery code): ");
                    outcome = await auth.VerifyMfaAsync(outcome.MfaToken!, (Console.ReadLine() ?? "").Trim());
                    continue;
                case AuthStatus.MfaEnrollRequired:
                    var enrollment = await auth.EnrollMfaAsync(outcome.MfaToken);
                    Console.WriteLine("This pool requires two-step verification. Add this account to your authenticator app:");
                    Console.WriteLine(enrollment.OtpauthUri);
                    Console.Write("First code: ");
                    var confirmation = await auth.ConfirmMfaAsync((Console.ReadLine() ?? "").Trim(), outcome.MfaToken);
                    Console.WriteLine("Recovery codes (keep them safe): " + string.Join(" ", confirmation.RecoveryCodes));
                    outcome = confirmation.Outcome!;
                    continue;
                case AuthStatus.PasswordChangeRequired:
                    Console.Write("You must choose a new password: ");
                    await auth.ChangeForcedPasswordAsync(outcome.ChangeToken!, ReadSecret());
                    Console.WriteLine("Password changed: sign in again.");
                    return false;
                case AuthStatus.VerificationRequired:
                    Console.WriteLine("Verify your email address first (check your inbox).");
                    return false;
                default:
                    Console.WriteLine("Unexpected status: " + outcome.StatusText);
                    return false;
            }
        }
    }

    private static string ReadSecret()
    {
        if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
            sb.Append(key.KeyChar);
        }
        Console.WriteLine();
        return sb.ToString();
    }
}
