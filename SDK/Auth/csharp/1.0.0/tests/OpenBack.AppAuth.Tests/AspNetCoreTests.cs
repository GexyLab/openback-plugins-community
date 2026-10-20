using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenBack.AppAuth.AspNetCore;
using Xunit;

namespace OpenBack.AppAuth.Tests
{
    public class AspNetCoreTests : IAsyncLifetime
    {
        private readonly TestKeys _keys = new TestKeys();
        private IHost? _host;
        private HttpClient _client = null!;

        public async Task InitializeAsync()
        {
            var jwks = new FakeHttp().OnJson("GET", "/gateway/shop/auth/main/.well-known/jwks.json", 200, TestKeys.Jwks(_keys));
            _host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddOpenBackAppAuth(o =>
                        {
                            o.Issuer = TestKeys.Issuer;
                            o.ClientIds = new[] { TestKeys.ClientId };
                            o.Backchannel = new HttpClient(jwks);
                        });
                        services.AddAuthorization(o =>
                        {
                            o.AddAppUserPolicy("admins", p => p.RequireAppRole("admin", "owner"));
                            o.AddAppUserPolicy("orders", p => p.RequireAppPermission("orders.read"));
                            o.AddAppUserPolicy("verified", p => p.RequireVerifiedAppEmail());
                            o.AddAppUserPolicy("guests", p => p.RequireAppUserOrGuest());
                        });
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseAuthorization();
                        app.UseEndpoints(e =>
                        {
                            e.MapGet("/me", (HttpContext ctx) => new
                            {
                                sub = ctx.User.FindFirst("sub")!.Value,
                                name = ctx.User.Identity!.Name,
                                admin = ctx.User.IsInRole("admin"),
                                member = ctx.User.IsInRole("member"),
                                org = ctx.User.FindFirst("org_id")?.Value,
                                perms = ctx.User.FindAll("permission").Select(c => c.Value).ToArray(),
                                appUser = ctx.GetAppUser()!.Id,
                            }).RequireAuthorization();
                            e.MapGet("/admin", () => "ok").RequireAuthorization("admins");
                            e.MapGet("/orders", () => "ok").RequireAuthorization("orders");
                            e.MapGet("/verified", () => "ok").RequireAuthorization("verified");
                            e.MapGet("/guests", () => "ok").RequireAuthorization("guests");
                            e.MapGet("/public", () => "ok");
                        });
                    }))
                .StartAsync();
            _client = _host.GetTestClient();
        }

        public async Task DisposeAsync()
        {
            if (_host != null) await _host.StopAsync();
            _host?.Dispose();
            _keys.Dispose();
        }

        private Task<HttpResponseMessage> Get(string path, string? token)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, path);
            if (token != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return _client.SendAsync(req);
        }

        private static async Task AssertError(HttpResponseMessage res, HttpStatusCode status, string error)
        {
            Assert.Equal(status, res.StatusCode);
            Assert.Equal($"Bearer error=\"{error}\"", res.Headers.WwwAuthenticate.ToString());
            Assert.Equal($"{{\"error\":\"{error}\"}}", await res.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task Missing_token_answers_401_invalid_token()
        {
            await AssertError(await Get("/me", null), HttpStatusCode.Unauthorized, "invalid_token");
            Assert.Equal(HttpStatusCode.OK, (await Get("/public", null)).StatusCode);
        }

        [Fact]
        public async Task Invalid_tokens_answer_401()
        {
            await AssertError(await Get("/me", "garbage"), HttpStatusCode.Unauthorized, "invalid_token");
            var expired = _keys.AccessToken(c => c["exp"] = TestKeys.Now - 600);
            await AssertError(await Get("/me", expired), HttpStatusCode.Unauthorized, "invalid_token");
            await AssertError(await Get("/me", _keys.AccessToken(c => c["aud"] = "uapp_other")), HttpStatusCode.Unauthorized, "invalid_token");
            await AssertError(await Get("/me", _keys.Sign(TestKeys.AccessClaims(), alg: "HS256")), HttpStatusCode.Unauthorized, "invalid_token");
        }

        [Fact]
        public async Task Valid_token_builds_the_principal()
        {
            var res = await Get("/me", _keys.AccessToken());
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            var body = await res.Content.ReadAsStringAsync();
            Assert.Contains("\"sub\":\"usr_1\"", body);
            Assert.Contains("\"name\":\"usr_1\"", body);
            Assert.Contains("\"admin\":false", body);
            Assert.Contains("\"member\":true", body);
            Assert.Contains("\"org\":\"org_1\"", body);
            Assert.Contains("\"perms\":[\"orders.read\"]", body);
            Assert.Contains("\"appUser\":\"usr_1\"", body);
        }

        [Fact]
        public async Task Guests_are_refused_by_default_with_403()
        {
            var guest = _keys.AccessToken(c => c["anon"] = true);
            await AssertError(await Get("/me", guest), HttpStatusCode.Forbidden, "insufficient_scope");
            Assert.Equal(HttpStatusCode.OK, (await Get("/guests", guest)).StatusCode);
        }

        [Fact]
        public async Task Role_permission_and_verified_email_policies()
        {
            await AssertError(await Get("/admin", _keys.AccessToken()), HttpStatusCode.Forbidden, "insufficient_scope");
            Assert.Equal(HttpStatusCode.OK, (await Get("/admin", _keys.AccessToken(c => c["roles"] = new[] { "owner" }))).StatusCode);

            Assert.Equal(HttpStatusCode.OK, (await Get("/orders", _keys.AccessToken())).StatusCode);
            await AssertError(await Get("/orders", _keys.AccessToken(c => c["permissions"] = new[] { "x" })), HttpStatusCode.Forbidden, "insufficient_scope");
            Assert.Equal(HttpStatusCode.OK, (await Get("/orders", _keys.AccessToken(c => c["permissions"] = new[] { "*" }))).StatusCode);

            Assert.Equal(HttpStatusCode.OK, (await Get("/verified", _keys.AccessToken())).StatusCode);
            await AssertError(await Get("/verified", _keys.AccessToken(c => c["email_verified"] = false)), HttpStatusCode.Forbidden, "insufficient_scope");

            await AssertError(await Get("/admin", null), HttpStatusCode.Unauthorized, "invalid_token");
        }
    }
}
