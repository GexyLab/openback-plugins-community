using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>Options of <see cref="TokenVerifier"/>.</summary>
    public sealed class TokenVerifierOptions
    {
        /// <summary>The pool's address (the tokens' <c>iss</c>, exact match; a trailing slash is ignored).</summary>
        public string Issuer { get; set; } = "";
        /// <summary>The client IDs accepted as <c>aud</c> (at least one).</summary>
        public IList<string> ClientIds { get; set; } = new List<string>();
        /// <summary>Default <c>&lt;issuer&gt;/.well-known/jwks.json</c>.</summary>
        public string? JwksUri { get; set; }
        /// <summary>How long the keys are kept (default 10 minutes).</summary>
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(10);
        /// <summary>A token signed by an unknown key refetches the keys at most this often (default 30 s).</summary>
        public TimeSpan UnknownKeyRefetchInterval { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Tolerance on <c>exp</c>, <c>nbf</c>, <c>iat</c> (default 60 s).</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);
        /// <summary>The HTTP client used to read the keys (default: a new one owned by the verifier).</summary>
        public HttpClient? HttpClient { get; set; }
        /// <summary>The clock (tests). Default <see cref="DateTimeOffset.UtcNow"/>.</summary>
        public Func<DateTimeOffset>? Clock { get; set; }
    }

    /// <summary>
    /// Verifies the pool's tokens locally (no call to OpenBack): ES256 signature with the pool's JWKS (cached, refetched on
    /// an unknown <c>kid</c> at most once per 30 s), only <c>ES256</c> accepted (no <c>none</c>, HS*, RS*), <c>typ</c>,
    /// <c>iss</c>, <c>aud</c>, <c>exp</c>/<c>nbf</c>/<c>iat</c> with leeway. Thread-safe: make one per pool and reuse it.
    /// Access tokens cannot be revoked before they expire: keep them short-lived (the pool's default is 15 minutes).
    /// </summary>
    public sealed class TokenVerifier : IDisposable
    {
        private readonly TokenVerifierOptions _options;
        private readonly string _issuer;
        private readonly string[] _clientIds;
        private readonly string _jwksUri;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly Func<DateTimeOffset> _clock;
        private readonly SemaphoreSlim _fetchLock = new SemaphoreSlim(1, 1);
        private volatile KeySet? _keySet;

        public TokenVerifier(string issuer, params string[] clientIds)
            : this(new TokenVerifierOptions { Issuer = issuer, ClientIds = clientIds.ToList() })
        {
        }

        public TokenVerifier(TokenVerifierOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _issuer = Internal.Issuer.Normalize(options.Issuer);
            _clientIds = (options.ClientIds ?? new List<string>()).Where(c => !string.IsNullOrEmpty(c)).Distinct().ToArray();
            if (_clientIds.Length == 0) throw new ArgumentException("At least one client ID is required.", nameof(options));
            _jwksUri = string.IsNullOrEmpty(options.JwksUri) ? _issuer + "/.well-known/jwks.json" : options.JwksUri!;
            _http = options.HttpClient ?? new HttpClient();
            _ownsHttp = options.HttpClient == null;
            _clock = options.Clock ?? (() => DateTimeOffset.UtcNow);
        }

        public string Issuer => _issuer;
        public IReadOnlyList<string> ClientIds => _clientIds;

        /// <summary>Verifies an access token (<c>typ: at+jwt</c>) and returns its user.</summary>
        /// <exception cref="TokenVerificationException">The token is not valid.</exception>
        /// <exception cref="AppAuthException">The keys could not be read (<c>jwks_unavailable</c>).</exception>
        public async Task<AppUser> VerifyAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            var claims = await VerifyJwtAsync(accessToken, accessToken: true, cancellationToken).ConfigureAwait(false);
            return AppUser.From(claims, Jwt.MatchedAudience(claims, _clientIds) ?? "");
        }

        /// <summary>Verifies an ID token (<c>typ: JWT</c>, <c>aud</c> = a client ID) and, when given, its <c>nonce</c>.</summary>
        public async Task<JsonElement> VerifyIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
        {
            var claims = await VerifyJwtAsync(idToken, accessToken: false, cancellationToken).ConfigureAwait(false);
            if (expectedNonce != null && !Crypto.FixedTimeEquals(Json.Str(claims, "nonce"), expectedNonce))
                throw new TokenVerificationException("invalid_nonce", "The ID token's nonce does not match.");
            return claims;
        }

        private async Task<JsonElement> VerifyJwtAsync(string token, bool accessToken, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(token)) throw Fail("malformed_token", "No token.");
            var parts = token.Split('.');
            if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
                throw Fail("malformed_token", "Not a signed JWT.");
            JsonElement header, claims;
            byte[] signature;
            try
            {
                header = Json.Parse(Encoding.UTF8.GetString(Base64Url.Decode(parts[0])));
                claims = Json.Parse(Encoding.UTF8.GetString(Base64Url.Decode(parts[1])));
                signature = Base64Url.Decode(parts[2]);
            }
            catch (Exception e) when (e is FormatException || e is JsonException || e is ArgumentException)
            {
                throw Fail("malformed_token", "The token cannot be decoded.");
            }
            if (header.ValueKind != JsonValueKind.Object || claims.ValueKind != JsonValueKind.Object)
                throw Fail("malformed_token", "The token's header or claims are not objects.");

            // Algorithm confusion: ONLY ES256, whatever the token says.
            if (Json.Str(header, "alg") != "ES256") throw Fail("invalid_algorithm", "Only ES256 tokens are accepted.");
            if (header.TryGetProperty("crit", out _)) throw Fail("malformed_token", "Unsupported critical header.");
            var typ = Json.Str(header, "typ");
            if (accessToken)
            {
                if (typ == null || !(string.Equals(typ, "at+jwt", StringComparison.OrdinalIgnoreCase) ||
                                     string.Equals(typ, "application/at+jwt", StringComparison.OrdinalIgnoreCase)))
                    throw Fail("invalid_type", "Not an access token (typ at+jwt).");
            }
            else if (typ != null && !string.Equals(typ, "JWT", StringComparison.OrdinalIgnoreCase))
            {
                throw Fail("invalid_type", "Not an ID token (typ JWT).");
            }
            if (signature.Length != 64) throw Fail("invalid_signature", "Bad ES256 signature length.");

            var kid = Json.Str(header, "kid") ?? "";
            var key = await KeyAsync(kid, ct).ConfigureAwait(false);
            bool valid;
            try
            {
                using (var ecdsa = ECDsa.Create(key))
                {
                    // JOSE signatures are R||S (IEEE P1363), the default format of .NET's ECDsa.
                    valid = ecdsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256);
                }
            }
            catch (CryptographicException)
            {
                valid = false;   // a key the platform refuses (e.g. not on the curve)
            }
            if (!valid) throw Fail("invalid_signature", "The token's signature is not valid.");

            if (Json.Str(claims, "iss") != _issuer) throw Fail("invalid_issuer", "The token was issued by another pool.");
            if (!Jwt.AudienceMatches(claims, _clientIds)) throw Fail("invalid_audience", "The token was issued to another app.");
            var now = _clock().ToUnixTimeSeconds();
            var skew = (long)_options.ClockSkew.TotalSeconds;
            var exp = Json.Num(claims, "exp");
            if (exp == null) throw Fail("malformed_token", "The token has no expiry.");
            if (now > exp.Value + skew) throw Fail("token_expired", "The token has expired.");
            var nbf = Json.Num(claims, "nbf");
            if (nbf != null && now + skew < nbf.Value) throw Fail("token_not_yet_valid", "The token is not valid yet.");
            var iat = Json.Num(claims, "iat");
            if (iat != null && now + skew < iat.Value) throw Fail("token_not_yet_valid", "The token was issued in the future.");
            if (string.IsNullOrEmpty(Json.Str(claims, "sub"))) throw Fail("malformed_token", "The token has no subject.");
            return claims;
        }

        private async Task<ECParameters> KeyAsync(string kid, CancellationToken ct)
        {
            var now = _clock();
            var set = _keySet;
            if (set == null || now >= set.ExpiresAt)
                set = await FetchAsync(force: false, ct).ConfigureAwait(false);
            if (set.Keys.TryGetValue(kid, out var key)) return key;
            // Unknown key: the pool may have rotated. Refetch, but at most once per interval (no amplification).
            if (now - set.FetchedAt >= _options.UnknownKeyRefetchInterval)
            {
                set = await FetchAsync(force: true, ct).ConfigureAwait(false);
                if (set.Keys.TryGetValue(kid, out key)) return key;
            }
            throw Fail("unknown_key", "The token was signed by an unknown key.");
        }

        private async Task<KeySet> FetchAsync(bool force, CancellationToken ct)
        {
            await _fetchLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var now = _clock();
                var current = _keySet;
                // Another caller fetched while this one waited.
                if (current != null && now < current.ExpiresAt && (!force || now - current.FetchedAt < _options.UnknownKeyRefetchInterval))
                    return current;
                JsonElement body;
                try
                {
                    using (var request = new HttpRequestMessage(HttpMethod.Get, _jwksUri))
                    {
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        using (var response = await _http.SendAsync(request, ct).ConfigureAwait(false))
                        {
                            var text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                            if (!response.IsSuccessStatusCode)
                                throw new AppAuthException((int)response.StatusCode, "jwks_unavailable", "The pool's keys could not be read.");
                            body = Json.Parse(text);
                        }
                    }
                }
                catch (Exception e) when (!(e is OperationCanceledException && ct.IsCancellationRequested))
                {
                    if (current == null)
                        throw e as AppAuthException ?? new AppAuthException(0, "jwks_unavailable", "The pool's keys could not be read.", null, e);
                    // Keep serving the last good keys; try again after the refetch interval (not at every request).
                    _keySet = new KeySet(current.Keys, now, now + _options.UnknownKeyRefetchInterval);
                    return _keySet;
                }
                _keySet = new KeySet(ParseJwks(body), now, now + _options.CacheDuration);
                return _keySet;
            }
            finally
            {
                _fetchLock.Release();
            }
        }

        /// <summary>An immutable snapshot of the keys (read without locks).</summary>
        private sealed class KeySet
        {
            public KeySet(Dictionary<string, ECParameters> keys, DateTimeOffset fetchedAt, DateTimeOffset expiresAt)
            {
                Keys = keys;
                FetchedAt = fetchedAt;
                ExpiresAt = expiresAt;
            }

            public Dictionary<string, ECParameters> Keys { get; }
            public DateTimeOffset FetchedAt { get; }
            public DateTimeOffset ExpiresAt { get; }
        }

        /// <summary>The usable keys of a JWK Set: EC P-256 with a kid, alg ES256 (or none), use sig (or none).</summary>
        internal static Dictionary<string, ECParameters> ParseJwks(JsonElement jwks)
        {
            var keys = new Dictionary<string, ECParameters>(StringComparer.Ordinal);
            if (jwks.ValueKind != JsonValueKind.Object || !jwks.TryGetProperty("keys", out var list) || list.ValueKind != JsonValueKind.Array)
                return keys;
            foreach (var jwk in list.EnumerateArray())
            {
                var kid = Json.Str(jwk, "kid");
                if (string.IsNullOrEmpty(kid) || Json.Str(jwk, "kty") != "EC" || Json.Str(jwk, "crv") != "P-256") continue;
                var alg = Json.Str(jwk, "alg");
                if (alg != null && alg != "ES256") continue;
                var use = Json.Str(jwk, "use");
                if (use != null && use != "sig") continue;
                try
                {
                    var x = Base64Url.Decode(Json.Str(jwk, "x") ?? "");
                    var y = Base64Url.Decode(Json.Str(jwk, "y") ?? "");
                    if (x.Length != 32 || y.Length != 32) continue;
                    var parameters = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
                    parameters.Validate();
                    keys[kid!] = parameters;
                }
                catch (Exception e) when (e is FormatException || e is CryptographicException)
                {
                    // Skip a broken key.
                }
            }
            return keys;
        }

        private static TokenVerificationException Fail(string code, string message) => new TokenVerificationException(code, message);

        public void Dispose()
        {
            if (_ownsHttp) _http.Dispose();
            _fetchLock.Dispose();
        }
    }
}
