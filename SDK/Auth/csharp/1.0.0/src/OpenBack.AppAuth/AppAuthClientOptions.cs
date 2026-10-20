using System;
using System.Net.Http;

namespace OpenBack.AppAuth
{
    /// <summary>Options of <see cref="AppAuthClient"/>. All optional.</summary>
    public sealed class AppAuthClientOptions
    {
        /// <summary>The registered redirect URI of the hosted sign-in: a custom scheme (<c>com.example.app:/callback</c>),
        /// an https address, or a loopback address for desktop apps (<c>http://127.0.0.1:53682/callback</c>).</summary>
        public string? RedirectUri { get; set; }

        /// <summary>Where the session is kept. Default: <see cref="InMemoryTokenStorage"/> (lost at exit). Windows desktop
        /// apps: <see cref="ProtectedFileTokenStorage"/>.</summary>
        public ITokenStorage? Storage { get; set; }

        /// <summary>The storage key. Default <c>openback.auth.&lt;clientId&gt;</c>.</summary>
        public string? StorageKey { get; set; }

        /// <summary>The HTTP client for the pool's API (default: a new one owned by the client). Its BaseAddress is not
        /// used; do NOT put <see cref="AppAuthHttpHandler"/> in its pipeline.</summary>
        public HttpClient? HttpClient { get; set; }

        /// <summary>Only for <c>web</c> / <c>backend</c> apps (confidential): sent with <c>client_secret_basic</c> when the
        /// hosted sign-in's code is exchanged. Never put a secret in a desktop, mobile or browser app.</summary>
        public string? ClientSecret { get; set; }

        /// <summary>The access token is renewed when it expires within this margin (default 60 s).</summary>
        public TimeSpan RefreshSkew { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>The clock (tests). Default <see cref="DateTimeOffset.UtcNow"/>.</summary>
        public Func<DateTimeOffset>? Clock { get; set; }
    }

    /// <summary>Options of <see cref="AppAuthClient.SignInWithSystemBrowserAsync"/> (desktop loopback sign-in).</summary>
    public sealed class SystemBrowserOptions
    {
        /// <summary>The loopback redirect URI registered for the app, e.g. <c>http://127.0.0.1:53682/callback</c> (a fixed
        /// port: the pool matches redirect URIs exactly). Default: the client's <see cref="AppAuthClientOptions.RedirectUri"/>.</summary>
        public string? RedirectUri { get; set; }

        /// <summary>How long to wait for the user (default 5 minutes).</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>Opens the URL. Default: the system browser (<c>Process.Start</c> with shell execute on Windows,
        /// <c>open</c> on macOS, <c>xdg-open</c> on Linux).</summary>
        public Func<Uri, System.Threading.Tasks.Task>? OpenBrowser { get; set; }

        /// <summary>The HTML page shown in the browser after a successful sign-in.</summary>
        public string SuccessHtml { get; set; } =
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed in</title></head><body style=\"font-family:sans-serif;text-align:center;padding:3em\"><h1>Signed in</h1><p>You can close this window and go back to the app.</p></body></html>";

        /// <summary>The HTML page shown in the browser when the sign-in failed.</summary>
        public string ErrorHtml { get; set; } =
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in failed</title></head><body style=\"font-family:sans-serif;text-align:center;padding:3em\"><h1>Sign-in failed</h1><p>Go back to the app and try again.</p></body></html>";
    }
}
