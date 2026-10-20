using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OpenBack.AppAuth.Tests
{
    /// <summary>A request as the fake server saw it (body read eagerly).</summary>
    public sealed class SeenRequest
    {
        public HttpMethod Method { get; set; } = HttpMethod.Get;
        public Uri Url { get; set; } = new Uri("http://x");
        public string Path => Url.AbsolutePath;
        public string Body { get; set; } = "";
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string? ContentType { get; set; }

        public JsonElement Json => JsonDocument.Parse(Body).RootElement;

        public Dictionary<string, string> Form => Body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace('+', ' ')), p => p.Length > 1 ? Uri.UnescapeDataString(p[1].Replace('+', ' ')) : "");
    }

    /// <summary>A mocked HTTP layer: routes by "METHOD /path" (path only, no query), records every request.</summary>
    public sealed class FakeHttp : HttpMessageHandler
    {
        private readonly ConcurrentDictionary<string, Func<SeenRequest, Task<HttpResponseMessage>>> _routes =
            new ConcurrentDictionary<string, Func<SeenRequest, Task<HttpResponseMessage>>>();

        public ConcurrentQueue<SeenRequest> Requests { get; } = new ConcurrentQueue<SeenRequest>();

        public int Count(string method, string path) => Requests.Count(r => r.Method.Method == method && r.Path == path);

        public SeenRequest Last(string method, string path) => Requests.Last(r => r.Method.Method == method && r.Path == path);

        public FakeHttp On(string method, string path, Func<SeenRequest, Task<HttpResponseMessage>> handler)
        {
            _routes[method + " " + path] = handler;
            return this;
        }

        public FakeHttp On(string method, string path, Func<SeenRequest, HttpResponseMessage> handler) =>
            On(method, path, r => Task.FromResult(handler(r)));

        public FakeHttp OnJson(string method, string path, int status, object body) =>
            On(method, path, _ => JsonResponse(status, body));

        public static HttpResponseMessage JsonResponse(int status, object body)
        {
            return new HttpResponseMessage((HttpStatusCode)status)
            {
                Content = new StringContent(body is string s ? s : JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
            };
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var seen = new SeenRequest
            {
                Method = request.Method,
                Url = request.RequestUri!,
                Body = request.Content == null ? "" : await request.Content.ReadAsStringAsync(cancellationToken),
                ContentType = request.Content?.Headers.ContentType?.MediaType,
            };
            foreach (var h in request.Headers) seen.Headers[h.Key] = string.Join(",", h.Value);
            Requests.Enqueue(seen);
            if (_routes.TryGetValue(request.Method.Method + " " + request.RequestUri!.AbsolutePath, out var handler))
                return await handler(seen);
            return JsonResponse(404, new { detail = "Not Found" });
        }
    }

    /// <summary>An ES256 key of the fake pool, its JWKS and a token signer.</summary>
    public sealed class TestKeys : IDisposable
    {
        public const string Issuer = "https://api.example.com/gateway/shop/auth/main";
        public const string ClientId = "uapp_test";
        public const string PoolId = "upool_test";

        public TestKeys(string kid = "k_test")
        {
            Kid = kid;
            Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }

        public string Kid { get; }
        public ECDsa Key { get; }

        public object Jwk
        {
            get
            {
                var p = Key.ExportParameters(false);
                return new { kty = "EC", crv = "P-256", x = B64(p.Q.X!), y = B64(p.Q.Y!), kid = Kid, alg = "ES256", use = "sig" };
            }
        }

        public static object Jwks(params TestKeys[] keys) => new { keys = keys.Select(k => k.Jwk).ToArray() };

        public static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        public static Dictionary<string, object?> AccessClaims(Action<Dictionary<string, object?>>? change = null)
        {
            var now = Now;
            var claims = new Dictionary<string, object?>
            {
                ["iss"] = Issuer, ["sub"] = "usr_1", ["aud"] = ClientId, ["azp"] = ClientId, ["exp"] = now + 900, ["iat"] = now,
                ["jti"] = "at_1", ["sid"] = "sess_1", ["pool"] = PoolId, ["sv"] = 1, ["org_id"] = "org_1",
                ["roles"] = new[] { "member" }, ["permissions"] = new[] { "orders.read" }, ["email"] = "ada@example.com",
                ["email_verified"] = true, ["amr"] = new[] { "pwd" }, ["scope"] = "openid profile email",
            };
            change?.Invoke(claims);
            return claims;
        }

        public string Sign(object claims, string typ = "at+jwt", string alg = "ES256", string? kid = null, Dictionary<string, object?>? extraHeader = null)
        {
            var header = new Dictionary<string, object?> { ["alg"] = alg, ["typ"] = typ, ["kid"] = kid ?? Kid };
            if (extraHeader != null) foreach (var kv in extraHeader) header[kv.Key] = kv.Value;
            var h = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
            var c = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(claims)));
            var sig = Key.SignData(Encoding.ASCII.GetBytes(h + "." + c), HashAlgorithmName.SHA256);   // IEEE P1363 (R||S)
            return h + "." + c + "." + B64(sig);
        }

        public string AccessToken(Action<Dictionary<string, object?>>? change = null) => Sign(AccessClaims(change));

        public void Dispose() => Key.Dispose();
    }

    public static class Pool
    {
        public static object User(string id = "usr_1") => new
        {
            id, email = "ada@example.com", email_verified = true, display_name = "Ada", photo_url = (string?)null, locale = "en",
            attributes = new { plan = "pro" }, anonymous = false, created_at = "2026-10-01T10:00:00", last_login_at = (string?)null,
            mfa = new { totp = false },
        };

        public static object Ok(string access = "at_1", string refresh = "obur_1", int expiresIn = 900, object? org = null) => new
        {
            status = "ok", access_token = access, refresh_token = refresh, expires_in = expiresIn, token_type = "Bearer",
            user = User(), org,
        };

        public static object Tokens(string access, string refresh, int expiresIn = 900) => new
        {
            access_token = access, token_type = "Bearer", expires_in = expiresIn, scope = "openid profile email",
            refresh_token = refresh, refresh_expires_in = 1209600, org = (object?)null,
        };

        public static object Error(string code, string message = "msg") => new { detail = new { code, message } };
    }

    /// <summary>A controllable clock.</summary>
    public sealed class TestClock
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public void Advance(TimeSpan by) => Now = Now + by;
    }
}
