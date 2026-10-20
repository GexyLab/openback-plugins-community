using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace OpenBack.AppAuth.Tests
{
    public class AppAuthClientTests
    {
        private const string Api = "/gateway/shop/auth/main/api/v1";

        private static (AppAuthClient client, FakeHttp http, InMemoryTokenStorage storage, TestClock clock) Make(ITokenStorage? storage = null)
        {
            var http = new FakeHttp();
            var clock = new TestClock();
            var store = storage as InMemoryTokenStorage ?? new InMemoryTokenStorage();
            var client = new AppAuthClient(TestKeys.Issuer + "/", TestKeys.ClientId, new AppAuthClientOptions
            {
                HttpClient = new HttpClient(http), Storage = storage ?? store, Clock = () => clock.Now,
                RedirectUri = "com.example.app:/callback",
            });
            return (client, http, store, clock);
        }

        [Fact]
        public async Task Password_sign_in_ok_keeps_the_session_and_notifies()
        {
            var (client, http, storage, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            var seen = new List<string?>();
            using (client.OnAuthStateChanged((user, org) => seen.Add(user?.Id)))
            {
                var outcome = await client.SignInWithPasswordAsync("ada@example.com", "secret-password");
                Assert.Equal(AuthStatus.Ok, outcome.Status);
                Assert.True(outcome.IsOk);
                Assert.Equal("usr_1", outcome.User!.Id);
            }
            Assert.Equal(new string?[] { null, "usr_1" }, seen);   // called immediately, then on sign-in
            Assert.True(client.IsSignedIn);
            Assert.Equal("Ada", client.CurrentUser!.DisplayName);
            Assert.Equal("pro", client.CurrentUser.Attributes!["plan"].GetString());

            var req = http.Last("POST", Api + "/signin/password");
            Assert.Equal(TestKeys.ClientId, req.Headers["X-Client-Id"]);
            Assert.Equal("application/json", req.ContentType);
            Assert.Equal("ada@example.com", req.Json.GetProperty("email").GetString());
            Assert.False(req.Json.TryGetProperty("org_id", out _));   // null members are not sent
            Assert.False(req.Headers.ContainsKey("Authorization"));

            var stored = JsonDocument.Parse((await storage.GetAsync("openback.auth." + TestKeys.ClientId))!).RootElement;
            Assert.Equal("at_1", stored.GetProperty("accessToken").GetString());
            Assert.Equal("obur_1", stored.GetProperty("refreshToken").GetString());
            Assert.True(stored.GetProperty("expiresAt").GetInt64() > 0);
            Assert.Equal("usr_1", stored.GetProperty("user").GetProperty("id").GetString());
        }

        [Fact]
        public async Task Mfa_required_is_returned_and_nothing_is_kept_until_verified()
        {
            var (client, http, storage, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, new { status = "mfa_required", mfa_token = "mfa_abc" });
            http.OnJson("POST", Api + "/signin/mfa", 200, Pool.Ok());
            var outcome = await client.SignInWithPasswordAsync("ada@example.com", "pw");
            Assert.Equal(AuthStatus.MfaRequired, outcome.Status);
            Assert.Equal("mfa_abc", outcome.MfaToken);
            Assert.False(client.IsSignedIn);
            Assert.Null(await storage.GetAsync("openback.auth." + TestKeys.ClientId));

            var done = await client.VerifyMfaAsync(outcome.MfaToken!, "123456");
            Assert.True(done.IsOk);
            Assert.True(client.IsSignedIn);
            var body = http.Last("POST", Api + "/signin/mfa").Json;
            Assert.Equal("mfa_abc", body.GetProperty("mfa_token").GetString());
            Assert.Equal("123456", body.GetProperty("code").GetString());
        }

        [Theory]
        [InlineData("verification_required", AuthStatus.VerificationRequired)]
        [InlineData("mfa_enroll_required", AuthStatus.MfaEnrollRequired)]
        [InlineData("password_change_required", AuthStatus.PasswordChangeRequired)]
        [InlineData("something_new", AuthStatus.Other)]
        public async Task Other_outcomes_are_typed(string status, AuthStatus expected)
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signup", 200, new { status, mfa_token = "m", change_token = "c" });
            var outcome = await client.SignUpAsync("a@example.com", "pw");
            Assert.Equal(expected, outcome.Status);
            Assert.Equal(status, outcome.StatusText);
            Assert.False(client.IsSignedIn);
        }

        [Fact]
        public async Task Forced_password_change_posts_the_change_token()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/password/reset", 200, new { status = "password_changed" });
            var result = await client.ChangeForcedPasswordAsync("chg_1", "new-password-1");
            Assert.Equal("password_changed", result.Status);
            var body = http.Last("POST", Api + "/password/reset").Json;
            Assert.Equal("chg_1", body.GetProperty("change_token").GetString());
            Assert.Equal("new-password-1", body.GetProperty("new_password").GetString());
        }

        [Fact]
        public async Task Errors_are_mapped_from_every_detail_shape()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 401, Pool.Error("invalid_credentials", "Wrong email or password"));
            var e1 = await Assert.ThrowsAsync<AppAuthException>(() => client.SignInWithPasswordAsync("a@b.c", "x"));
            Assert.Equal(401, e1.Status);
            Assert.Equal("invalid_credentials", e1.Code);
            Assert.Equal("Wrong email or password", e1.Message);

            http.OnJson("POST", Api + "/signup", 422, new { detail = new { code = "weak_password", message = "weak", problems = new[] { "min_length", "digit" } } });
            var e2 = await Assert.ThrowsAsync<AppAuthException>(() => client.SignUpAsync("a@b.c", "x"));
            Assert.Equal("weak_password", e2.Code);
            Assert.Equal(new[] { "min_length", "digit" }, e2.Problems);

            http.OnJson("POST", Api + "/signin/email-code", 422, new { detail = "invalid email" });
            var e3 = await Assert.ThrowsAsync<AppAuthException>(() => client.SendEmailCodeAsync("nope"));
            Assert.Equal("http_422", e3.Code);
            Assert.Equal("invalid email", e3.Message);

            http.OnJson("POST", Api + "/password/forgot", 422, new { detail = new[] { new { loc = new[] { "body", "email" }, msg = "field required" } } });
            var e4 = await Assert.ThrowsAsync<AppAuthException>(() => client.SendPasswordResetAsync(""));
            Assert.Equal("http_422", e4.Code);
            Assert.Equal("field required", e4.Message);

            http.On("GET", Api + "/config", _ => new HttpResponseMessage(System.Net.HttpStatusCode.BadGateway) { Content = new StringContent("<html>") });
            var e5 = await Assert.ThrowsAsync<AppAuthException>(() => client.GetConfigAsync());
            Assert.Equal(502, e5.Status);
            Assert.Equal("http_502", e5.Code);
        }

        [Fact]
        public async Task Fresh_token_is_returned_without_a_refresh_and_a_stale_one_is_renewed()
        {
            var (client, http, storage, clock) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok("at_1", "obur_1", 900));
            http.OnJson("POST", Api + "/token/refresh", 200, Pool.Tokens("at_2", "obur_2"));
            await client.SignInWithPasswordAsync("a@b.c", "pw");

            Assert.Equal("at_1", await client.GetAccessTokenAsync());
            clock.Advance(TimeSpan.FromSeconds(900 - 61));
            Assert.Equal("at_1", await client.GetAccessTokenAsync());
            Assert.Equal(0, http.Count("POST", Api + "/token/refresh"));

            clock.Advance(TimeSpan.FromSeconds(2));   // 59 s left: renew
            Assert.Equal("at_2", await client.GetAccessTokenAsync());
            Assert.Equal(1, http.Count("POST", Api + "/token/refresh"));
            Assert.Equal("obur_1", http.Last("POST", Api + "/token/refresh").Json.GetProperty("refresh_token").GetString());
            var stored = JsonDocument.Parse((await storage.GetAsync(client.StorageKey))!).RootElement;
            Assert.Equal("obur_2", stored.GetProperty("refreshToken").GetString());   // rotated token stored
            Assert.Equal("usr_1", client.CurrentUser!.Id);                               // user kept
        }

        [Fact]
        public async Task Concurrent_callers_share_one_refresh()
        {
            var (client, http, _, clock) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok("at_1", "obur_1", 900));
            var gate = new TaskCompletionSource<bool>();
            http.On("POST", Api + "/token/refresh", async _ =>
            {
                await gate.Task;
                return FakeHttp.JsonResponse(200, Pool.Tokens("at_2", "obur_2"));
            });
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            clock.Advance(TimeSpan.FromSeconds(1000));

            var calls = Enumerable.Range(0, 10).Select(_ => Task.Run(() => client.GetAccessTokenAsync())).ToArray();
            await Task.Delay(100);
            gate.SetResult(true);
            var tokens = await Task.WhenAll(calls);
            Assert.All(tokens, t => Assert.Equal("at_2", t));
            Assert.Equal(1, http.Count("POST", Api + "/token/refresh"));

            // Explicit refreshes started together also share one request.
            gate = new TaskCompletionSource<bool>();
            http.On("POST", Api + "/token/refresh", async _ =>
            {
                await gate.Task;
                return FakeHttp.JsonResponse(200, Pool.Tokens("at_3", "obur_3"));
            });
            var explicitCalls = Enumerable.Range(0, 5).Select(_ => client.RefreshAsync()).ToArray();
            await Task.Delay(50);
            gate.SetResult(true);
            Assert.All(await Task.WhenAll(explicitCalls), t => Assert.Equal("at_3", t));
            Assert.Equal(2, http.Count("POST", Api + "/token/refresh"));
        }

        [Fact]
        public async Task Refused_refresh_clears_the_session_and_notifies_signed_out()
        {
            var (client, http, storage, clock) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.OnJson("POST", Api + "/token/refresh", 401, Pool.Error("invalid_refresh_token"));
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            var states = new List<bool>();
            client.AuthStateChanged += (s, e) => states.Add(e.IsSignedIn);
            clock.Advance(TimeSpan.FromHours(1));

            var e1 = await Assert.ThrowsAsync<AppAuthException>(() => client.GetAccessTokenAsync());
            Assert.Equal("invalid_refresh_token", e1.Code);
            Assert.True(e1.IsSessionEnded);
            Assert.False(client.IsSignedIn);
            Assert.Null(client.CurrentUser);
            Assert.Null(await storage.GetAsync(client.StorageKey));
            Assert.Equal(new[] { false }, states);

            var e2 = await Assert.ThrowsAsync<AppAuthException>(() => client.GetAccessTokenAsync());
            Assert.Equal("not_signed_in", e2.Code);
        }

        [Fact]
        public async Task A_token_401_on_a_signed_in_call_clears_the_session()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.OnJson("GET", Api + "/me", 401, Pool.Error("token_revoked"));
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            var e = await Assert.ThrowsAsync<AppAuthException>(() => client.MeAsync());
            Assert.Equal("token_revoked", e.Code);
            Assert.False(client.IsSignedIn);
            Assert.Equal("Bearer at_1", http.Last("GET", Api + "/me").Headers["Authorization"]);
        }

        [Fact]
        public async Task Other_errors_on_signed_in_calls_keep_the_session()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.OnJson("POST", Api + "/orgs", 403, Pool.Error("org_creation_disabled"));
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            var e = await Assert.ThrowsAsync<AppAuthException>(() => client.CreateOrganizationAsync("Acme"));
            Assert.Equal("org_creation_disabled", e.Code);
            Assert.True(client.IsSignedIn);
        }

        [Fact]
        public async Task Network_error_during_refresh_is_surfaced_not_retried_and_the_session_is_kept()
        {
            var (client, http, _, clock) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.On("POST", Api + "/token/refresh", (Func<SeenRequest, HttpResponseMessage>)(_ => throw new HttpRequestException("connection reset")));
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            clock.Advance(TimeSpan.FromHours(1));
            var e = await Assert.ThrowsAsync<AppAuthException>(() => client.GetAccessTokenAsync());
            Assert.Equal(0, e.Status);
            Assert.Equal("network_error", e.Code);
            Assert.Equal(1, http.Count("POST", Api + "/token/refresh"));
            Assert.True(client.IsSignedIn);
        }

        [Fact]
        public async Task Sign_out_clears_locally_even_when_the_server_fails()
        {
            var (client, http, storage, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.OnJson("POST", Api + "/signout", 500, new { detail = "boom" });
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            await client.SignOutAsync(everywhere: true);
            Assert.False(client.IsSignedIn);
            Assert.Null(await storage.GetAsync(client.StorageKey));
            var body = http.Last("POST", Api + "/signout").Json;
            Assert.Equal("obur_1", body.GetProperty("refresh_token").GetString());
            Assert.True(body.GetProperty("everywhere").GetBoolean());
        }

        [Fact]
        public async Task Change_password_and_delete_account_clear_the_session()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.OnJson("POST", Api + "/me/password", 200, new { status = "password_changed", signed_out = true });
            http.OnJson("DELETE", Api + "/me", 200, new { status = "deleted" });
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            await client.ChangePasswordAsync("pw", "new-password-1");
            Assert.False(client.IsSignedIn);

            await client.SignInWithPasswordAsync("a@b.c", "new-password-1");
            var r = await client.DeleteAccountAsync("new-password-1");
            Assert.Equal("deleted", r.Status);
            Assert.False(client.IsSignedIn);
            Assert.Equal("new-password-1", http.Last("DELETE", Api + "/me").Json.GetProperty("password").GetString());
        }

        [Fact]
        public async Task The_stored_session_is_restored_by_a_new_client()
        {
            var storage = new InMemoryTokenStorage();
            var (first, http, _, _) = Make(storage);
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            await first.SignInWithPasswordAsync("a@b.c", "pw");

            var second = await AppAuthClient.CreateAsync(TestKeys.Issuer, TestKeys.ClientId,
                new AppAuthClientOptions { Storage = storage, HttpClient = new HttpClient(new FakeHttp()) });
            Assert.True(second.IsSignedIn);
            Assert.Equal("usr_1", second.CurrentUser!.Id);
        }

        [Fact]
        public async Task Refresh_uses_the_newer_token_rotated_by_another_process()
        {
            var storage = new InMemoryTokenStorage();
            var (a, http, _, clock) = Make(storage);
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok("at_1", "obur_1"));
            http.OnJson("POST", Api + "/token/refresh", 200, Pool.Tokens("at_3", "obur_3"));
            await a.SignInWithPasswordAsync("a@b.c", "pw");
            // Another process renewed and stored obur_2 (stale now).
            var raw = (await storage.GetAsync(a.StorageKey))!.Replace("obur_1", "obur_2");
            await storage.SetAsync(a.StorageKey, raw);
            clock.Advance(TimeSpan.FromHours(1));
            Assert.Equal("at_3", await a.GetAccessTokenAsync());
            Assert.Equal("obur_2", http.Last("POST", Api + "/token/refresh").Json.GetProperty("refresh_token").GetString());
        }

        [Fact]
        public async Task Authorized_handler_adds_the_bearer_token()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            var api = new FakeHttp().OnJson("GET", "/orders", 200, new { ok = true });
            using (var httpClient = new HttpClient(new AppAuthHttpHandler(client, api)))
            {
                var res = await httpClient.GetAsync("https://api.example.com/orders");
                Assert.True(res.IsSuccessStatusCode);
            }
            Assert.Equal("Bearer at_1", api.Last("GET", "/orders").Headers["Authorization"]);
        }

        [Fact]
        public async Task Organization_switch_rotates_tokens_and_updates_the_org()
        {
            var (client, http, storage, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok("at_1", "obur_1", 900, new { id = "org_a", name = "A", roles = new[] { "owner" }, choices = 2 }));
            http.OnJson("POST", Api + "/orgs/switch", 200, new
            {
                access_token = "at_2", token_type = "Bearer", expires_in = 900, refresh_token = "obur_2",
                org = new { id = "org_b", name = "B", roles = new[] { "member" }, choices = 2 },
            });
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            Assert.Equal("org_a", client.CurrentOrg!.Id);
            var org = await client.SwitchOrganizationAsync("org_b");
            Assert.Equal("org_b", org!.Id);
            Assert.Equal("org_b", client.CurrentOrg!.Id);
            var body = http.Last("POST", Api + "/orgs/switch").Json;
            Assert.Equal("obur_1", body.GetProperty("refresh_token").GetString());
            Assert.Contains("obur_2", (await storage.GetAsync(client.StorageKey))!);
        }

        [Fact]
        public async Task Members_calls_escape_ids_and_send_query()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/signin/password", 200, Pool.Ok());
            http.OnJson("GET", Api + "/orgs/org_1/members", 200, new { items = new[] { new { user_id = "usr_2", email = "b@x", roles = new[] { "admin" } } }, total = 1, roles = new[] { new { key = "admin", label = "Admin" } } });
            http.OnJson("POST", Api + "/orgs/org_1/members", 201, new { user_id = "usr_3", email = "c@x", roles = new[] { "member" }, created = true, temporary_password = "tmp" });
            await client.SignInWithPasswordAsync("a@b.c", "pw");
            var page = await client.GetMembersAsync("org_1", "b", 0, 20);
            Assert.Equal("usr_2", page.Items[0].UserId);
            Assert.Equal("admin", page.Roles[0].Key);
            Assert.Contains("limit=20", http.Last("GET", Api + "/orgs/org_1/members").Url.Query);
            var added = await client.AddMemberAsync("org_1", "c@x", roles: new[] { "member" });
            Assert.True(added.Created);
            Assert.Equal("tmp", added.TemporaryPassword);
            Assert.Equal("member", http.Last("POST", Api + "/orgs/org_1/members").Json.GetProperty("roles")[0].GetString());
        }

        [Fact]
        public async Task Mfa_enrollment_with_an_mfa_token_returns_recovery_codes_and_signs_in()
        {
            var (client, http, _, _) = Make();
            http.OnJson("POST", Api + "/mfa/enroll", 200, new { secret = "JBSWY3DP", otpauth_uri = "otpauth://totp/x" });
            http.OnJson("POST", Api + "/mfa/enroll/confirm", 200, new
            {
                status = "ok", access_token = "at_1", refresh_token = "obur_1", expires_in = 900, user = Pool.User(),
                recovery_codes = new[] { "r1", "r2" },
            });
            var enrollment = await client.EnrollMfaAsync("mfa_t");
            Assert.Equal("otpauth://totp/x", enrollment.OtpauthUri);
            var confirmed = await client.ConfirmMfaAsync("123456", "mfa_t");
            Assert.Equal(new[] { "r1", "r2" }, confirmed.RecoveryCodes);
            Assert.True(confirmed.Outcome!.IsOk);
            Assert.True(client.IsSignedIn);
        }
    }
}
