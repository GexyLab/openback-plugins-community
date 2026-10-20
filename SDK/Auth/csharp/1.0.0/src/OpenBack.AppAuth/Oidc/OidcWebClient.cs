using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>How a confidential app authenticates at the token endpoint.</summary>
    public enum ClientAuthMethod
    {
        /// <summary><c>client_secret_basic</c> (default): HTTP Basic with the url-encoded ID and secret.</summary>
        ClientSecretBasic,
        /// <summary><c>client_secret_post</c>: <c>client_id</c> and <c>client_secret</c> in the form.</summary>
        ClientSecretPost,
    }

    /// <summary>Options of <see cref="OidcWebClient"/>.</summary>
    public sealed class OidcWebClientOptions
    {
        public string Issuer { get; set; } = "";
        public string ClientId { get; set; } = "";
        /// <summary>The app's client secret (kind <c>web</c>). Keep it in configuration secrets, never in source.</summary>
        public string? ClientSecret { get; set; }
        /// <summary>The registered redirect URI (exact match), e.g. <c>https://app.example.com/auth/callback</c>.</summary>
        public string RedirectUri { get; set; } = "";
        public ClientAuthMethod ClientAuthMethod { get; set; } = ClientAuthMethod.ClientSecretBasic;
        /// <summary>Default <c>openid profile email</c>.</summary>
        public string? Scope { get; set; }
        public HttpClient? HttpClient { get; set; }
        /// <summary>The verifier of the ID tokens (default: one made from the issuer and client ID, sharing the HTTP client).</summary>
        public TokenVerifier? TokenVerifier { get; set; }
        public Func<DateTimeOffset>? Clock { get; set; }
    }

    /// <summary>The result of <see cref="OidcWebClient.HandleCallbackAsync(IEnumerable{KeyValuePair{string,string}}, OidcTransaction, CancellationToken)"/>.</summary>
    public sealed class OidcCallbackResult
    {
        internal OidcCallbackResult(TokenSet tokens, JsonElement? idTokenClaims)
        {
            Tokens = tokens;
            IdTokenClaims = idTokenClaims;
        }

        public TokenSet Tokens { get; }
        /// <summary>The VERIFIED claims of the ID token (signature, iss, aud, exp, nonce); null without the openid scope.</summary>
        public JsonElement? IdTokenClaims { get; }
        /// <summary>The user id (<c>sub</c>).</summary>
        public string? Subject => IdTokenClaims.HasValue ? Json.Str(IdTokenClaims.Value, "sub") : null;
    }

    /// <summary>
    /// OpenID Connect for <c>web</c> apps with their own server (confidential: client secret). The app keeps the
    /// <see cref="OidcTransaction"/> in its server-side session between <see cref="CreateAuthorizationRequest"/> and
    /// <see cref="HandleCallbackAsync(IEnumerable{KeyValuePair{string,string}}, OidcTransaction, CancellationToken)"/>.
    /// PKCE S256 is always used, also with a secret.
    /// </summary>
    public sealed class OidcWebClient : IDisposable
    {
        private readonly OidcWebClientOptions _options;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly TokenVerifier _verifier;
        private readonly bool _ownsVerifier;
        private readonly Func<DateTimeOffset> _clock;

        public OidcWebClient(OidcWebClientOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrWhiteSpace(options.ClientId)) throw new ArgumentException("ClientId is required.", nameof(options));
            if (string.IsNullOrWhiteSpace(options.RedirectUri)) throw new ArgumentException("RedirectUri is required.", nameof(options));
            Issuer = Internal.Issuer.Normalize(options.Issuer);
            _http = options.HttpClient ?? new HttpClient();
            _ownsHttp = options.HttpClient == null;
            _clock = options.Clock ?? (() => DateTimeOffset.UtcNow);
            _verifier = options.TokenVerifier ?? new TokenVerifier(new TokenVerifierOptions
            {
                Issuer = Issuer, ClientIds = new List<string> { options.ClientId }, HttpClient = _http, Clock = options.Clock,
            });
            _ownsVerifier = options.TokenVerifier == null;
        }

        public string Issuer { get; }
        public string ClientId => _options.ClientId;

        /// <summary>The authorization URL and the transaction to keep in the user's session (server-side).</summary>
        public AuthorizationRequest CreateAuthorizationRequest(AuthorizationRequestOptions? options = null)
        {
            var o = options ?? new AuthorizationRequestOptions();
            if (o.Scope == null && _options.Scope != null)
                o = new AuthorizationRequestOptions
                {
                    Provider = o.Provider, OrgId = o.OrgId, Prompt = o.Prompt, ScreenHint = o.ScreenHint, LoginHint = o.LoginHint,
                    MaxAge = o.MaxAge, Scope = _options.Scope, UiLocales = o.UiLocales, RedirectUri = o.RedirectUri,
                };
            var tx = OidcProtocol.NewTransaction(o.RedirectUri ?? _options.RedirectUri, _clock());
            return new AuthorizationRequest(OidcProtocol.AuthorizeUrl(Issuer, ClientId, tx, o), tx);
        }

        /// <summary>Completes the sign-in from the callback's query parameters: checks error, state (constant time), iss;
        /// exchanges the code with the client secret and PKCE verifier; verifies the ID token (signature, iss, aud, exp,
        /// nonce). Remove the transaction from the session afterwards (one use).</summary>
        public async Task<OidcCallbackResult> HandleCallbackAsync(IEnumerable<KeyValuePair<string, string>> callbackParameters,
            OidcTransaction transaction, CancellationToken cancellationToken = default)
        {
            if (transaction == null) throw new AppAuthException(400, "invalid_state", "No sign-in in progress.");
            var query = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var p in callbackParameters)
                if (!query.ContainsKey(p.Key)) query[p.Key] = p.Value;
            var code = OidcProtocol.CheckCallback(query, transaction, Issuer);
            var data = await TokenAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = transaction.RedirectUri,
                ["code_verifier"] = transaction.CodeVerifier,
            }, cancellationToken).ConfigureAwait(false);
            var tokens = TokenSet.From(data, _clock());
            JsonElement? claims = null;
            if (tokens.IdToken != null)
                claims = await _verifier.VerifyIdTokenAsync(tokens.IdToken, transaction.Nonce, cancellationToken).ConfigureAwait(false);
            return new OidcCallbackResult(tokens, claims);
        }

        /// <summary>Same as the other overload, from the full callback URL (or its query string).</summary>
        public Task<OidcCallbackResult> HandleCallbackAsync(string callbackUrl, OidcTransaction transaction, CancellationToken cancellationToken = default)
        {
            return HandleCallbackAsync(Query.Parse(callbackUrl ?? ""), transaction, cancellationToken);
        }

        /// <summary>New tokens for a refresh token (ROTATED: store the new one; one refresh at a time per session).</summary>
        public async Task<TokenSet> RefreshAsync(string refreshToken, string? orgId = null, CancellationToken cancellationToken = default)
        {
            var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken };
            if (!string.IsNullOrEmpty(orgId)) form["org_id"] = orgId!;
            return TokenSet.From(await TokenAsync(form, cancellationToken).ConfigureAwait(false), _clock());
        }

        /// <summary>Revokes a refresh token and its whole family (RFC 7009).</summary>
        public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, Issuer + "/revoke"))
            {
                var form = new Dictionary<string, string> { ["token"] = refreshToken, ["token_type_hint"] = "refresh_token" };
                AddClientAuth(request, form);
                request.Content = new FormUrlEncodedContent(form);
                await HttpCall.SendAsync(_http, request, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>The OIDC userinfo of an access token (checks, on the pool, that the session is still open).</summary>
        public async Task<UserInfo> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, Issuer + "/userinfo"))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                return Json.To<UserInfo>(await HttpCall.SendAsync(_http, request, cancellationToken).ConfigureAwait(false)) ?? new UserInfo();
            }
        }

        /// <summary>The hosted sign-out URL. <paramref name="postLogoutRedirectUri"/> must be registered for the app.</summary>
        public Uri BuildLogoutUrl(string? idTokenHint = null, string? postLogoutRedirectUri = null, string? state = null)
        {
            var p = new List<KeyValuePair<string, string?>>
            {
                new KeyValuePair<string, string?>("client_id", ClientId),
                new KeyValuePair<string, string?>("id_token_hint", idTokenHint),
                new KeyValuePair<string, string?>("post_logout_redirect_uri", postLogoutRedirectUri),
                new KeyValuePair<string, string?>("state", state),
            };
            return new Uri(Issuer + "/logout?" + Query.Build(p));
        }

        private async Task<JsonElement> TokenAsync(Dictionary<string, string> form, CancellationToken ct)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, Issuer + "/token"))
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                AddClientAuth(request, form);
                request.Content = new FormUrlEncodedContent(form);
                return await HttpCall.SendAsync(_http, request, ct).ConfigureAwait(false);
            }
        }

        private void AddClientAuth(HttpRequestMessage request, Dictionary<string, string> form)
        {
            var secret = _options.ClientSecret;
            if (string.IsNullOrEmpty(secret))
            {
                form["client_id"] = ClientId;           // public client: PKCE only
                return;
            }
            if (_options.ClientAuthMethod == ClientAuthMethod.ClientSecretPost)
            {
                form["client_id"] = ClientId;
                form["client_secret"] = secret!;
            }
            else
            {
                request.Headers.Authorization = HttpCall.BasicAuth(ClientId, secret!);
            }
        }

        public void Dispose()
        {
            if (_ownsVerifier) _verifier.Dispose();
            if (_ownsHttp) _http.Dispose();
        }
    }
}
