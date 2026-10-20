using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace OpenBack.AppAuth.Tests
{
    public class TokenVerifierTests : IDisposable
    {
        private const string JwksPath = "/gateway/shop/auth/main/.well-known/jwks.json";
        private readonly TestKeys _keys = new TestKeys();
        private readonly FakeHttp _http = new FakeHttp();
        private readonly TestClock _clock = new TestClock();
        private readonly TokenVerifier _verifier;

        public TokenVerifierTests()
        {
            _http.OnJson("GET", JwksPath, 200, TestKeys.Jwks(_keys));
            _verifier = new TokenVerifier(new TokenVerifierOptions
            {
                Issuer = TestKeys.Issuer, ClientIds = new List<string> { TestKeys.ClientId, "uapp_other" },
                HttpClient = new HttpClient(_http), Clock = () => _clock.Now,
            });
        }

        public void Dispose()
        {
            _verifier.Dispose();
            _keys.Dispose();
        }

        private async Task<string> Refused(string token)
        {
            var e = await Assert.ThrowsAsync<TokenVerificationException>(() => _verifier.VerifyAsync(token));
            Assert.Equal(401, e.Status);
            return e.Code;
        }

        [Fact]
        public async Task A_valid_access_token_gives_the_app_user()
        {
            var token = _keys.AccessToken(c => { c["anon"] = true; c["attr"] = new { plan = "pro" }; c["permissions"] = new[] { "*" }; });
            var user = await _verifier.VerifyAsync(token);
            Assert.Equal("usr_1", user.Id);
            Assert.Equal(TestKeys.PoolId, user.PoolId);
            Assert.Equal(TestKeys.ClientId, user.ClientId);
            Assert.Equal("ada@example.com", user.Email);
            Assert.True(user.EmailVerified);
            Assert.True(user.Anonymous);
            Assert.Equal("org_1", user.OrgId);
            Assert.Equal("sess_1", user.SessionId);
            Assert.Equal(new[] { "pwd" }, user.Amr);
            Assert.True(user.HasRole("member"));
            Assert.False(user.HasRole("admin"));
            Assert.True(user.HasPermission("anything"));   // "*"
            Assert.Equal("pro", user.Attributes["plan"].GetString());
            Assert.Equal("at_1", user.Claims.GetProperty("jti").GetString());
        }

        [Fact]
        public async Task Permissions_without_star_are_exact()
        {
            var user = await _verifier.VerifyAsync(_keys.AccessToken());
            Assert.True(user.HasPermission("orders.read"));
            Assert.False(user.HasPermission("orders.write"));
        }

        [Theory]
        [InlineData("none")]
        [InlineData("HS256")]
        [InlineData("RS256")]
        [InlineData("ES384")]
        [InlineData("es256")]
        public async Task Only_ES256_is_accepted(string alg)
        {
            Assert.Equal("invalid_algorithm", await Refused(_keys.Sign(TestKeys.AccessClaims(), alg: alg)));
        }

        [Fact]
        public async Task Alg_none_with_an_empty_signature_is_refused()
        {
            var header = TestKeys.B64(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"at+jwt\"}"));
            var claims = TestKeys.B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(TestKeys.AccessClaims())));
            Assert.Equal("malformed_token", await Refused(header + "." + claims + "."));
        }

        [Fact]
        public async Task HS256_signed_with_the_public_key_is_refused()
        {
            // Classic confusion attack: HMAC keyed with the public JWK.
            var header = TestKeys.B64(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"at+jwt\",\"kid\":\"k_test\"}"));
            var claims = TestKeys.B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(TestKeys.AccessClaims())));
            using (var hmac = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(_keys.Jwk))))
            {
                var sig = TestKeys.B64(hmac.ComputeHash(Encoding.ASCII.GetBytes(header + "." + claims)));
                Assert.Equal("invalid_algorithm", await Refused(header + "." + claims + "." + sig));
            }
        }

        [Theory]
        [InlineData("JWT")]
        [InlineData("jwt")]
        [InlineData("refresh")]
        public async Task Access_tokens_need_typ_at_jwt(string typ)
        {
            Assert.Equal("invalid_type", await Refused(_keys.Sign(TestKeys.AccessClaims(), typ: typ)));
        }

        [Theory]
        [InlineData("at+jwt")]
        [InlineData("AT+JWT")]
        [InlineData("application/at+jwt")]
        public async Task Typ_variants_are_accepted(string typ)
        {
            Assert.Equal("usr_1", (await _verifier.VerifyAsync(_keys.Sign(TestKeys.AccessClaims(), typ: typ))).Id);
        }

        [Fact]
        public async Task Issuer_must_match_exactly()
        {
            Assert.Equal("invalid_issuer", await Refused(_keys.AccessToken(c => c["iss"] = TestKeys.Issuer + "/")));
            Assert.Equal("invalid_issuer", await Refused(_keys.AccessToken(c => c["iss"] = "https://evil.example.com/gateway/shop/auth/main")));
        }

        [Fact]
        public async Task Audience_must_be_a_configured_client()
        {
            Assert.Equal("invalid_audience", await Refused(_keys.AccessToken(c => { c["aud"] = "uapp_evil"; })));
            Assert.Equal("uapp_other", (await _verifier.VerifyAsync(_keys.AccessToken(c => c["aud"] = "uapp_other"))).ClientId);
        }

        [Fact]
        public async Task Expiry_honours_the_leeway()
        {
            var now = _clock.Now.ToUnixTimeSeconds();
            Assert.Equal("usr_1", (await _verifier.VerifyAsync(_keys.AccessToken(c => c["exp"] = now - 30))).Id);
            Assert.Equal("token_expired", await Refused(_keys.AccessToken(c => c["exp"] = now - 61)));
            Assert.Equal("token_not_yet_valid", await Refused(_keys.AccessToken(c => c["nbf"] = now + 120)));
            Assert.Equal("token_not_yet_valid", await Refused(_keys.AccessToken(c => c["iat"] = now + 120)));
            Assert.Equal("malformed_token", await Refused(_keys.AccessToken(c => c.Remove("exp"))));
        }

        [Fact]
        public async Task Tampered_or_foreign_signatures_are_refused()
        {
            var token = _keys.AccessToken();
            var parts = token.Split('.');
            var forged = TestKeys.B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(TestKeys.AccessClaims(c => c["roles"] = new[] { "admin" }))));
            Assert.Equal("invalid_signature", await Refused(parts[0] + "." + forged + "." + parts[2]));

            using (var other = new TestKeys("k_test"))   // same kid, another key
                Assert.Equal("invalid_signature", await Refused(other.AccessToken()));

            Assert.Equal("invalid_signature", await Refused(parts[0] + "." + parts[1] + "." + TestKeys.B64(new byte[70])));
            Assert.Equal("malformed_token", await Refused("not.a.jwt!"));
            Assert.Equal("malformed_token", await Refused("abc"));
        }

        [Fact]
        public async Task Keys_are_cached_and_refetched_after_the_cache_duration()
        {
            await _verifier.VerifyAsync(_keys.AccessToken());
            await _verifier.VerifyAsync(_keys.AccessToken());
            Assert.Equal(1, _http.Count("GET", JwksPath));
            _clock.Advance(TimeSpan.FromMinutes(11));
            await _verifier.VerifyAsync(_keys.Sign(TestKeys.AccessClaims(c => { c["exp"] = _clock.Now.ToUnixTimeSeconds() + 600; c["iat"] = _clock.Now.ToUnixTimeSeconds(); })));
            Assert.Equal(2, _http.Count("GET", JwksPath));
        }

        [Fact]
        public async Task Unknown_kid_refetches_at_most_once_per_30_seconds()
        {
            await _verifier.VerifyAsync(_keys.AccessToken());
            Assert.Equal(1, _http.Count("GET", JwksPath));

            // Within 30 s of the last fetch: no refetch, refused.
            using (var rotated = new TestKeys("k_new"))
            {
                Assert.Equal("unknown_key", await Refused(rotated.AccessToken()));
                Assert.Equal("unknown_key", await Refused(rotated.AccessToken()));
                Assert.Equal(1, _http.Count("GET", JwksPath));

                // The pool rotated: after 30 s, one refetch finds the new key.
                _http.OnJson("GET", JwksPath, 200, TestKeys.Jwks(_keys, rotated));
                _clock.Advance(TimeSpan.FromSeconds(31));
                var claims = TestKeys.AccessClaims(c => { c["exp"] = _clock.Now.ToUnixTimeSeconds() + 600; c["iat"] = _clock.Now.ToUnixTimeSeconds(); });
                Assert.Equal("usr_1", (await _verifier.VerifyAsync(rotated.Sign(claims))).Id);
                Assert.Equal(2, _http.Count("GET", JwksPath));

                // A flood of unknown kids does not hammer the pool.
                for (var i = 0; i < 5; i++) Assert.Equal("unknown_key", await Refused(_keys.Sign(claims, kid: "k_" + i)));
                Assert.Equal(2, _http.Count("GET", JwksPath));
            }
        }

        [Fact]
        public async Task Jwks_failure_is_reported_as_unavailable()
        {
            var http = new FakeHttp().OnJson("GET", JwksPath, 503, new { detail = "off" });
            using (var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = TestKeys.Issuer, ClientIds = new List<string> { TestKeys.ClientId }, HttpClient = new HttpClient(http) }))
            {
                var e = await Assert.ThrowsAsync<AppAuthException>(() => verifier.VerifyAsync(_keys.AccessToken()));
                Assert.Equal("jwks_unavailable", e.Code);
                Assert.IsNotType<TokenVerificationException>(e);
            }
        }

        [Fact]
        public async Task A_jwks_outage_keeps_the_last_good_keys_and_retries_with_backoff()
        {
            await _verifier.VerifyAsync(_keys.AccessToken());
            _http.OnJson("GET", JwksPath, 503, new { detail = "down" });
            _clock.Advance(TimeSpan.FromMinutes(11));
            Func<string> fresh = () => _keys.Sign(TestKeys.AccessClaims(c => { c["exp"] = _clock.Now.ToUnixTimeSeconds() + 600; c["iat"] = _clock.Now.ToUnixTimeSeconds(); }));
            Assert.Equal("usr_1", (await _verifier.VerifyAsync(fresh())).Id);
            Assert.Equal("usr_1", (await _verifier.VerifyAsync(fresh())).Id);
            Assert.Equal(2, _http.Count("GET", JwksPath));   // one failed attempt, not one per request
            _clock.Advance(TimeSpan.FromSeconds(31));
            Assert.Equal("usr_1", (await _verifier.VerifyAsync(fresh())).Id);
            Assert.Equal(3, _http.Count("GET", JwksPath));
        }

        [Fact]
        public async Task Jwks_skips_unusable_keys()
        {
            _http.OnJson("GET", JwksPath, 200, new
            {
                keys = new object[]
                {
                    new { kty = "RSA", kid = "k_test", n = "AQAB", e = "AQAB" },
                    new { kty = "EC", crv = "P-384", kid = "k_test", x = "AA", y = "AA" },
                    new { kty = "oct", kid = "k_test", k = "c2VjcmV0" },
                },
            });
            Assert.Equal("unknown_key", await Refused(_keys.AccessToken()));
        }

        [Fact]
        public async Task Id_tokens_are_checked_with_typ_jwt_and_nonce()
        {
            var claims = TestKeys.AccessClaims(c => c["nonce"] = "n-123");
            var idToken = _keys.Sign(claims, typ: "JWT");
            var verified = await _verifier.VerifyIdTokenAsync(idToken, "n-123");
            Assert.Equal("usr_1", verified.GetProperty("sub").GetString());
            var e = await Assert.ThrowsAsync<TokenVerificationException>(() => _verifier.VerifyIdTokenAsync(idToken, "other"));
            Assert.Equal("invalid_nonce", e.Code);
            // An access token is not an ID token, and vice versa.
            var e2 = await Assert.ThrowsAsync<TokenVerificationException>(() => _verifier.VerifyIdTokenAsync(_keys.AccessToken()));
            Assert.Equal("invalid_type", e2.Code);
            Assert.Equal("invalid_type", await Refused(idToken));
        }

        [Fact]
        public void Unverified_decoding_is_available_for_display()
        {
            var claims = Jwt.DecodePayload(_keys.AccessToken());
            Assert.Equal("usr_1", claims!.Value.GetProperty("sub").GetString());
            Assert.Null(Jwt.DecodePayload("garbage"));
        }
    }
}
