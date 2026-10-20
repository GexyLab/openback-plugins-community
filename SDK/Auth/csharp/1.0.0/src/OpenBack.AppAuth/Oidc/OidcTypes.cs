using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>Options of a hosted sign-in (<c>&lt;issuer&gt;/authorize</c>). All optional.</summary>
    public sealed class AuthorizationRequestOptions
    {
        /// <summary>A provider id of the pool (<see cref="PoolProvider.Id"/>): straight to Google, Microsoft...</summary>
        public string? Provider { get; set; }
        /// <summary>B2B: the organization to sign in to.</summary>
        public string? OrgId { get; set; }
        /// <summary><c>none</c> (no page: <c>login_required</c> when there is no session) or <c>login</c> (always ask).</summary>
        public string? Prompt { get; set; }
        /// <summary><c>signup</c> to open the sign-up form.</summary>
        public string? ScreenHint { get; set; }
        public string? LoginHint { get; set; }
        /// <summary>Maximum age in seconds of the hosted session.</summary>
        public int? MaxAge { get; set; }
        /// <summary>Default <c>openid profile email</c>.</summary>
        public string? Scope { get; set; }
        /// <summary><c>it</c> or <c>en</c>.</summary>
        public string? UiLocales { get; set; }
        /// <summary>Overrides the client's redirect URI (it must be registered exactly).</summary>
        public string? RedirectUri { get; set; }
    }

    /// <summary>What must be kept between the start of a hosted sign-in and its callback (state, nonce, PKCE verifier,
    /// redirect URI). A secret: keep it server-side (session) or in protected storage. Serializable with
    /// <see cref="ToJson"/> / <see cref="FromJson"/>.</summary>
    public sealed class OidcTransaction
    {
        [JsonPropertyName("state")] public string State { get; set; } = "";
        [JsonPropertyName("nonce")] public string Nonce { get; set; } = "";
        [JsonPropertyName("verifier")] public string CodeVerifier { get; set; } = "";
        [JsonPropertyName("redirect")] public string RedirectUri { get; set; } = "";
        /// <summary>When the transaction was made (Unix ms).</summary>
        [JsonPropertyName("createdAt")] public long CreatedAt { get; set; }

        public string ToJson() => JsonSerializer.Serialize(this);

        public static OidcTransaction FromJson(string json)
        {
            var tx = JsonSerializer.Deserialize<OidcTransaction>(json);
            if (tx == null || string.IsNullOrEmpty(tx.State) || string.IsNullOrEmpty(tx.CodeVerifier))
                throw new FormatException("Not an OIDC transaction.");
            return tx;
        }

        public override string ToString() => "OidcTransaction(***)";
    }

    /// <summary>A prepared hosted sign-in: open <see cref="Url"/> in a browser; keep <see cref="Transaction"/> for the callback.</summary>
    public sealed class AuthorizationRequest
    {
        internal AuthorizationRequest(Uri url, OidcTransaction transaction)
        {
            Url = url;
            Transaction = transaction;
        }

        public Uri Url { get; }
        public OidcTransaction Transaction { get; }
        public string State => Transaction.State;
        public string Nonce => Transaction.Nonce;
        public string CodeVerifier => Transaction.CodeVerifier;
        public string RedirectUri => Transaction.RedirectUri;

        public override string ToString() => "AuthorizationRequest(" + Url.GetLeftPart(UriPartial.Path) + ")";
    }

    /// <summary>The tokens of an OIDC token answer. Never log them (<see cref="ToString"/> hides them).</summary>
    public sealed class TokenSet
    {
        public string AccessToken { get; internal set; } = "";
        public string TokenType { get; internal set; } = "Bearer";
        public int ExpiresIn { get; internal set; }
        /// <summary>When the access token expires (computed at reception).</summary>
        public DateTimeOffset ExpiresAt { get; internal set; }
        public string? Scope { get; internal set; }
        /// <summary>Rotated at every use: always store the new one.</summary>
        public string? RefreshToken { get; internal set; }
        public int? RefreshExpiresIn { get; internal set; }
        /// <summary>Only on the code exchange (not on refresh).</summary>
        public string? IdToken { get; internal set; }
        public ActiveOrg? Org { get; internal set; }

        internal static TokenSet From(JsonElement data, DateTimeOffset now)
        {
            var expires = (int)(Json.Num(data, "expires_in") ?? 900);
            JsonElement org = default;
            var hasOrg = data.ValueKind == JsonValueKind.Object && data.TryGetProperty("org", out org) && org.ValueKind == JsonValueKind.Object;
            var access = Json.Str(data, "access_token");
            if (string.IsNullOrEmpty(access)) throw new AppAuthException(502, "invalid_token_response", "The token answer has no access token.");
            return new TokenSet
            {
                AccessToken = access!,
                TokenType = Json.Str(data, "token_type") ?? "Bearer",
                ExpiresIn = expires,
                ExpiresAt = now.AddSeconds(expires),
                Scope = Json.Str(data, "scope"),
                RefreshToken = Json.Str(data, "refresh_token"),
                RefreshExpiresIn = (int?)Json.Num(data, "refresh_expires_in"),
                IdToken = Json.Str(data, "id_token"),
                Org = hasOrg ? Json.To<ActiveOrg>(org) : null,
            };
        }

        public override string ToString() => $"TokenSet(expires_in={ExpiresIn}, refresh={(RefreshToken != null ? "yes" : "no")}, id_token={(IdToken != null ? "yes" : "no")})";
    }

    /// <summary>The OIDC userinfo answer.</summary>
    public sealed class UserInfo
    {
        public string Sub { get; set; } = "";
        public string? Email { get; set; }
        public bool EmailVerified { get; set; }
        public string? Name { get; set; }
        public string? Picture { get; set; }
        public string? Locale { get; set; }
        public string? OrgId { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public Dictionary<string, JsonElement>? Attributes { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    /// <summary>Protocol pieces shared by <see cref="AppAuthClient"/> and <see cref="OidcWebClient"/>.</summary>
    internal static class OidcProtocol
    {
        public const string DefaultScope = "openid profile email";

        public static OidcTransaction NewTransaction(string redirectUri, DateTimeOffset now)
        {
            if (string.IsNullOrEmpty(redirectUri)) throw new InvalidOperationException("A redirect URI is required for the hosted sign-in.");
            return new OidcTransaction
            {
                State = Crypto.RandomString(16),
                Nonce = Crypto.RandomString(16),
                CodeVerifier = Crypto.RandomString(48),      // 64 characters, 384 bits
                RedirectUri = redirectUri,
                CreatedAt = now.ToUnixTimeMilliseconds(),
            };
        }

        public static Uri AuthorizeUrl(string issuer, string clientId, OidcTransaction tx, AuthorizationRequestOptions? o)
        {
            o = o ?? new AuthorizationRequestOptions();
            var p = new List<KeyValuePair<string, string?>>
            {
                new KeyValuePair<string, string?>("response_type", "code"),
                new KeyValuePair<string, string?>("client_id", clientId),
                new KeyValuePair<string, string?>("redirect_uri", tx.RedirectUri),
                new KeyValuePair<string, string?>("scope", string.IsNullOrWhiteSpace(o.Scope) ? DefaultScope : o.Scope),
                new KeyValuePair<string, string?>("state", tx.State),
                new KeyValuePair<string, string?>("nonce", tx.Nonce),
                new KeyValuePair<string, string?>("code_challenge", Crypto.CodeChallenge(tx.CodeVerifier)),
                new KeyValuePair<string, string?>("code_challenge_method", "S256"),
                new KeyValuePair<string, string?>("provider", o.Provider),
                new KeyValuePair<string, string?>("org_id", o.OrgId),
                new KeyValuePair<string, string?>("prompt", o.Prompt),
                new KeyValuePair<string, string?>("screen_hint", o.ScreenHint),
                new KeyValuePair<string, string?>("login_hint", o.LoginHint),
                new KeyValuePair<string, string?>("max_age", o.MaxAge?.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string?>("ui_locales", o.UiLocales),
            };
            return new Uri(issuer + "/authorize?" + Query.Build(p));
        }

        /// <summary>Checks a callback (error, state in constant time, iss per RFC 9207) and returns the code.</summary>
        public static string CheckCallback(IDictionary<string, string> query, OidcTransaction? tx, string issuer)
        {
            if (query.TryGetValue("error", out var error) && !string.IsNullOrEmpty(error))
            {
                query.TryGetValue("error_description", out var description);
                throw new AppAuthException(400, error, string.IsNullOrEmpty(description) ? error : description);
            }
            if (!query.TryGetValue("code", out var code) || string.IsNullOrEmpty(code))
                throw new AppAuthException(400, "invalid_request", "The callback has no authorization code.");
            query.TryGetValue("state", out var state);
            if (tx == null || !Crypto.FixedTimeEquals(tx.State, state))
                throw new AppAuthException(400, "invalid_state", "Sign-in state mismatch.");
            if (query.TryGetValue("iss", out var iss) && iss != null && iss != issuer)
                throw new AppAuthException(400, "invalid_issuer", "Unexpected issuer in the callback.");
            return code;
        }

        /// <summary>Unverified claims of an ID token, with the iss / aud / nonce checks of a token received directly from
        /// the token endpoint over TLS (OIDC Core 3.1.3.7).</summary>
        public static JsonElement CheckIdTokenUnverified(string idToken, string issuer, string clientId, string nonce)
        {
            var claims = Jwt.DecodePayload(idToken) ?? throw new AppAuthException(400, "invalid_id_token", "Malformed ID token.");
            if (Json.Str(claims, "iss") != issuer) throw new AppAuthException(400, "invalid_id_token", "ID token of another issuer.");
            if (!Jwt.AudienceMatches(claims, new[] { clientId })) throw new AppAuthException(400, "invalid_id_token", "ID token for another app.");
            if (!Crypto.FixedTimeEquals(Json.Str(claims, "nonce"), nonce)) throw new AppAuthException(400, "invalid_nonce", "Nonce mismatch.");
            return claims;
        }
    }
}
