using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace OpenBack.AppAuth.Tests
{
    public class OidcTests : IDisposable
    {
        private const string Base = "/gateway/shop/auth/main";
        private readonly TestKeys _keys = new TestKeys();

        public void Dispose() => _keys.Dispose();

        private static Dictionary<string, string> QueryOf(Uri url) =>
            url.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
                .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));

        private static string S256(string verifier)
        {
            using (var sha = SHA256.Create())
                return TestKeys.B64(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
        }

        private string IdToken(string nonce, string aud = TestKeys.ClientId) =>
            _keys.Sign(TestKeys.AccessClaims(c => { c["nonce"] = nonce; c["aud"] = aud; }), typ: "JWT");

        private (AppAuthClient client, FakeHttp http, InMemoryTokenStorage storage) MakeClient(string? secret = null)
        {
            var http = new FakeHttp();
            var storage = new InMemoryTokenStorage();
            var client = new AppAuthClient(TestKeys.Issuer, TestKeys.ClientId, new AppAuthClientOptions
            {
                HttpClient = new HttpClient(http), Storage = storage, RedirectUri = "com.example.app:/callback", ClientSecret = secret,
            });
            http.OnJson("GET", Base + "/api/v1/me", 200, Pool.User());
            return (client, http, storage);
        }

        [Fact]
        public async Task Authorization_request_has_pkce_s256_state_nonce_and_extras()
        {
            var (client, _, storage) = MakeClient();
            var req = await client.BuildAuthorizationRequestAsync(new AuthorizationRequestOptions
            {
                Provider = "uprov_google", OrgId = "org_1", Prompt = "login", ScreenHint = "signup", LoginHint = "ada@example.com",
                MaxAge = 300, UiLocales = "it",
            });
            Assert.Equal(TestKeys.Issuer + "/authorize", req.Url.GetLeftPart(UriPartial.Path));
            var q = QueryOf(req.Url);
            Assert.Equal("code", q["response_type"]);
            Assert.Equal(TestKeys.ClientId, q["client_id"]);
            Assert.Equal("com.example.app:/callback", q["redirect_uri"]);
            Assert.Equal("openid profile email", q["scope"]);
            Assert.Equal("S256", q["code_challenge_method"]);
            Assert.Equal(S256(req.CodeVerifier), q["code_challenge"]);
            Assert.Equal(req.State, q["state"]);
            Assert.Equal(req.Nonce, q["nonce"]);
            Assert.Equal("uprov_google", q["provider"]);
            Assert.Equal("org_1", q["org_id"]);
            Assert.Equal("login", q["prompt"]);
            Assert.Equal("signup", q["screen_hint"]);
            Assert.Equal("ada@example.com", q["login_hint"]);
            Assert.Equal("300", q["max_age"]);
            Assert.Equal("it", q["ui_locales"]);
            Assert.InRange(req.CodeVerifier.Length, 43, 128);
            Assert.NotNull(await storage.GetAsync(client.StorageKey + ".pkce"));

            var other = await client.BuildAuthorizationRequestAsync();
            Assert.NotEqual(req.State, other.State);
            Assert.NotEqual(req.CodeVerifier, other.CodeVerifier);
        }

        [Fact]
        public async Task Callback_exchanges_the_code_and_keeps_the_session()
        {
            var (client, http, storage) = MakeClient();
            var req = await client.BuildAuthorizationRequestAsync();
            http.On("POST", Base + "/token", r => FakeHttp.JsonResponse(200, new
            {
                access_token = "at_1", token_type = "Bearer", expires_in = 900, refresh_token = "obur_1", id_token = IdToken(req.Nonce),
            }));
            var user = await client.HandleRedirectCallbackAsync($"com.example.app:/callback?code=c_1&state={req.State}&iss={Uri.EscapeDataString(TestKeys.Issuer)}");
            Assert.Equal("usr_1", user!.Id);
            Assert.True(client.IsSignedIn);
            var form = http.Last("POST", Base + "/token").Form;
            Assert.Equal("authorization_code", form["grant_type"]);
            Assert.Equal("c_1", form["code"]);
            Assert.Equal(req.CodeVerifier, form["code_verifier"]);
            Assert.Equal("com.example.app:/callback", form["redirect_uri"]);
            Assert.Equal(TestKeys.ClientId, form["client_id"]);
            Assert.False(http.Last("POST", Base + "/token").Headers.ContainsKey("Authorization"));
            Assert.Null(await storage.GetAsync(client.StorageKey + ".pkce"));   // one use
            Assert.Contains("\"idToken\"", (await storage.GetAsync(client.StorageKey))!);
            Assert.Contains("id_token_hint=", client.BuildLogoutUrl("https://app.example.com/bye", "s1").Query);
        }

        [Fact]
        public async Task Callback_checks_state_iss_error_and_nonce()
        {
            var (client, http, _) = MakeClient();
            var req = await client.BuildAuthorizationRequestAsync();

            var e1 = await Assert.ThrowsAsync<AppAuthException>(() => client.HandleRedirectCallbackAsync("com.example.app:/callback?code=c&state=wrong"));
            Assert.Equal("invalid_state", e1.Code);

            var e2 = await Assert.ThrowsAsync<AppAuthException>(() =>
                client.HandleRedirectCallbackAsync($"com.example.app:/callback?code=c&state={req.State}&iss=https%3A%2F%2Fevil.example.com"));
            Assert.Equal("invalid_issuer", e2.Code);

            var e3 = await Assert.ThrowsAsync<AppAuthException>(() =>
                client.HandleRedirectCallbackAsync($"com.example.app:/callback?error=login_required&state={req.State}"));
            Assert.Equal("login_required", e3.Code);

            Assert.Null(await client.HandleRedirectCallbackAsync("com.example.app:/callback"));
            Assert.Equal(0, http.Count("POST", Base + "/token"));

            http.On("POST", Base + "/token", _ => FakeHttp.JsonResponse(200, new
            {
                access_token = "at_1", token_type = "Bearer", expires_in = 900, refresh_token = "obur_1", id_token = IdToken("another-nonce"),
            }));
            var e4 = await Assert.ThrowsAsync<AppAuthException>(() => client.HandleRedirectCallbackAsync($"x:/cb?code=c&state={req.State}"));
            Assert.Equal("invalid_nonce", e4.Code);
            Assert.False(client.IsSignedIn);

            var req2 = await client.BuildAuthorizationRequestAsync();
            http.OnJson("POST", Base + "/token", 400, new { error = "invalid_grant", error_description = "invalid or expired code" });
            var e5 = await Assert.ThrowsAsync<AppAuthException>(() => client.HandleRedirectCallbackAsync($"x:/cb?code=c&state={req2.State}"));
            Assert.Equal("invalid_grant", e5.Code);
            Assert.Equal("invalid or expired code", e5.Message);
        }

        [Fact]
        public async Task Confidential_client_sends_basic_auth_with_url_encoded_credentials()
        {
            var (client, http, _) = MakeClient(secret: "s3cr:t/+");
            var req = await client.BuildAuthorizationRequestAsync();
            http.OnJson("POST", Base + "/token", 200, new { access_token = "at_1", expires_in = 900, refresh_token = "obur_1" });
            await client.HandleRedirectCallbackAsync($"x:/cb?code=c&state={req.State}");
            var auth = http.Last("POST", Base + "/token").Headers["Authorization"];
            Assert.StartsWith("Basic ", auth);
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(auth.Substring(6)));
            Assert.Equal(TestKeys.ClientId + ":" + Uri.EscapeDataString("s3cr:t/+"), decoded);
        }

        // ------------------------------------------------------------------------------------------------- web client

        private (OidcWebClient web, FakeHttp http) MakeWeb(ClientAuthMethod method = ClientAuthMethod.ClientSecretBasic)
        {
            var http = new FakeHttp();
            http.OnJson("GET", Base + "/.well-known/jwks.json", 200, TestKeys.Jwks(_keys));
            var web = new OidcWebClient(new OidcWebClientOptions
            {
                Issuer = TestKeys.Issuer, ClientId = TestKeys.ClientId, ClientSecret = "secret", RedirectUri = "https://app.example.com/cb",
                ClientAuthMethod = method, HttpClient = new HttpClient(http),
            });
            return (web, http);
        }

        [Fact]
        public async Task Web_client_full_flow_with_verified_id_token()
        {
            var (web, http) = MakeWeb();
            var start = web.CreateAuthorizationRequest(new AuthorizationRequestOptions { Prompt = "login" });
            var tx = OidcTransaction.FromJson(start.Transaction.ToJson());   // round trip through the session
            Assert.Equal("https://app.example.com/cb", QueryOf(start.Url)["redirect_uri"]);
            http.OnJson("POST", Base + "/token", 200, new
            {
                access_token = _keys.AccessToken(), token_type = "Bearer", expires_in = 900, refresh_token = "obur_1",
                refresh_expires_in = 100, id_token = IdToken(tx.Nonce), scope = "openid profile email",
            });
            var result = await web.HandleCallbackAsync(new Dictionary<string, string> { ["code"] = "c", ["state"] = tx.State, ["iss"] = TestKeys.Issuer }, tx);
            Assert.Equal("usr_1", result.Subject);
            Assert.Equal("obur_1", result.Tokens.RefreshToken);
            Assert.DoesNotContain("obur_1", result.Tokens.ToString());
            var token = http.Last("POST", Base + "/token");
            Assert.StartsWith("Basic ", token.Headers["Authorization"]);
            Assert.False(token.Form.ContainsKey("client_secret"));
            Assert.Equal(tx.CodeVerifier, token.Form["code_verifier"]);

            var forged = IdToken("wrong");
            http.OnJson("POST", Base + "/token", 200, new { access_token = "a", expires_in = 900, id_token = forged });
            var e = await Assert.ThrowsAsync<TokenVerificationException>(() =>
                web.HandleCallbackAsync($"https://app.example.com/cb?code=c&state={tx.State}", tx));
            Assert.Equal("invalid_nonce", e.Code);

            var e2 = await Assert.ThrowsAsync<AppAuthException>(() => web.HandleCallbackAsync($"?code=c&state=bad", tx));
            Assert.Equal("invalid_state", e2.Code);
        }

        [Fact]
        public async Task Web_client_post_auth_refresh_revoke_userinfo_logout()
        {
            var (web, http) = MakeWeb(ClientAuthMethod.ClientSecretPost);
            http.OnJson("POST", Base + "/token", 200, Pool.Tokens("at_2", "obur_2"));
            http.On("POST", Base + "/revoke", _ => new HttpResponseMessage(HttpStatusCode.OK));
            http.OnJson("GET", Base + "/userinfo", 200, new { sub = "usr_1", email = "ada@example.com", email_verified = true, org_id = "org_1", roles = new[] { "member" } });

            var tokens = await web.RefreshAsync("obur_1", "org_2");
            Assert.Equal("obur_2", tokens.RefreshToken);
            var form = http.Last("POST", Base + "/token").Form;
            Assert.Equal("refresh_token", form["grant_type"]);
            Assert.Equal("org_2", form["org_id"]);
            Assert.Equal("secret", form["client_secret"]);
            Assert.Equal(TestKeys.ClientId, form["client_id"]);

            await web.RevokeAsync("obur_2");
            Assert.Equal("obur_2", http.Last("POST", Base + "/revoke").Form["token"]);

            var info = await web.GetUserInfoAsync("at_2");
            Assert.Equal("usr_1", info.Sub);
            Assert.Equal("Bearer at_2", http.Last("GET", Base + "/userinfo").Headers["Authorization"]);

            var logout = web.BuildLogoutUrl("idt", "https://app.example.com/bye", "s");
            var q = QueryOf(logout);
            Assert.Equal(TestKeys.ClientId, q["client_id"]);
            Assert.Equal("idt", q["id_token_hint"]);
            Assert.Equal("https://app.example.com/bye", q["post_logout_redirect_uri"]);
        }

        // ------------------------------------------------------------------------------------------- desktop loopback

        private static int FreePort()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        [Fact]
        public async Task Loopback_sign_in_receives_the_redirect_and_signs_in()
        {
            var (client, http, _) = MakeClient();
            var redirect = $"http://127.0.0.1:{FreePort()}/callback";
            string? nonce = null;
            http.On("POST", Base + "/token", _ => FakeHttp.JsonResponse(200, new
            {
                access_token = "at_1", token_type = "Bearer", expires_in = 900, refresh_token = "obur_1", id_token = IdToken(nonce!),
            }));
            HttpResponseMessage? browserPage = null;
            var user = await client.SignInWithSystemBrowserAsync(new SystemBrowserOptions
            {
                RedirectUri = redirect,
                Timeout = TimeSpan.FromSeconds(20),
                OpenBrowser = async url =>
                {
                    // A "browser": the hosted page redirects back to the loopback address.
                    var q = QueryOf(url);
                    Assert.Equal(redirect, q["redirect_uri"]);
                    nonce = q["nonce"];
                    var back = $"{redirect}?code=c_1&state={Uri.EscapeDataString(q["state"])}&iss={Uri.EscapeDataString(TestKeys.Issuer)}";
                    _ = Task.Run(async () =>
                    {
                        using (var browser = new HttpClient())
                        {
                            await browser.GetAsync($"http://127.0.0.1:{new Uri(redirect).Port}/favicon.ico");
                            browserPage = await browser.GetAsync(back);
                        }
                    });
                    await Task.CompletedTask;
                },
            });
            Assert.Equal("usr_1", user!.Id);
            Assert.True(client.IsSignedIn);
            Assert.Equal(redirect, http.Last("POST", Base + "/token").Form["redirect_uri"]);
            for (var i = 0; i < 50 && browserPage == null; i++) await Task.Delay(50);
            Assert.Equal(HttpStatusCode.OK, browserPage!.StatusCode);
        }

        [Fact]
        public async Task Loopback_sign_in_times_out()
        {
            var (client, _, _) = MakeClient();
            var e = await Assert.ThrowsAsync<AppAuthException>(() => client.SignInWithSystemBrowserAsync(new SystemBrowserOptions
            {
                RedirectUri = $"http://127.0.0.1:{FreePort()}/callback", Timeout = TimeSpan.FromMilliseconds(300),
                OpenBrowser = _ => Task.CompletedTask,
            }));
            Assert.Equal("timeout", e.Code);
        }

        [Fact]
        public async Task Loopback_needs_a_loopback_redirect()
        {
            var (client, _, _) = MakeClient();
            await Assert.ThrowsAsync<ArgumentException>(() => client.SignInWithSystemBrowserAsync(new SystemBrowserOptions
            {
                RedirectUri = "https://app.example.com/callback", OpenBrowser = _ => Task.CompletedTask,
            }));
        }
    }
}
