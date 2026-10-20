using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace OpenBack.AppAuth.AspNetCore
{
    /// <summary>
    /// Authenticates <c>Authorization: Bearer &lt;access token&gt;</c> with <see cref="TokenVerifier"/> (local ES256
    /// verification with the pool's keys). Missing or invalid token: 401 with
    /// <c>WWW-Authenticate: Bearer error="invalid_token"</c> and <c>{"error":"invalid_token"}</c>. Valid token but a policy
    /// refuses: 403 with <c>{"error":"insufficient_scope"}</c>.
    /// </summary>
    public sealed class OpenBackAppAuthHandler : AuthenticationHandler<OpenBackAppAuthOptions>
    {
        private readonly OpenBackAppAuthVerifiers _verifiers;

        public OpenBackAppAuthHandler(IOptionsMonitor<OpenBackAppAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder,
            OpenBackAppAuthVerifiers verifiers)
            : base(options, logger, encoder)
        {
            _verifiers = verifiers;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string? header = Request.Headers.Authorization;
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.NoResult();
            var token = header.Substring(7).Trim();
            if (token.Length == 0) return AuthenticateResult.NoResult();
            try
            {
                var user = await _verifiers.Get(Scheme.Name, Options).VerifyAsync(token, Context.RequestAborted).ConfigureAwait(false);
                Context.Items[OpenBackAppAuthDefaults.AppUserItemKey] = user;
                var principal = AppUserPrincipal.Create(user, Scheme.Name);
                return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
            }
            catch (TokenVerificationException e)
            {
                // Never log the token itself.
                Logger.LogDebug("OpenBack app token refused: {Code}", e.Code);
                return AuthenticateResult.Fail(e.Code);
            }
            catch (AppAuthException e)
            {
                Logger.LogWarning("OpenBack app token could not be verified: {Code}", e.Code);
                return AuthenticateResult.Fail(e.Code);
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            return WriteErrorAsync(StatusCodes.Status401Unauthorized, "invalid_token");
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            return WriteErrorAsync(StatusCodes.Status403Forbidden, "insufficient_scope");
        }

        private async Task WriteErrorAsync(int status, string error)
        {
            if (Response.HasStarted) return;
            Response.StatusCode = status;
            Response.Headers.Append(HeaderNames.WWWAuthenticate, "Bearer error=\"" + error + "\"");
            Response.Headers.CacheControl = "no-store";
            Response.ContentType = "application/json";
            await Response.WriteAsync("{\"error\":\"" + error + "\"}").ConfigureAwait(false);
        }
    }

    /// <summary>One <see cref="TokenVerifier"/> per scheme (its keys cache lives as long as the app). Registered as singleton.</summary>
    public sealed class OpenBackAppAuthVerifiers : IDisposable
    {
        private readonly ConcurrentDictionary<string, Lazy<TokenVerifier>> _verifiers = new ConcurrentDictionary<string, Lazy<TokenVerifier>>();

        public TokenVerifier Get(string scheme, OpenBackAppAuthOptions options)
        {
            return _verifiers.GetOrAdd(scheme, _ => new Lazy<TokenVerifier>(() => new TokenVerifier(new TokenVerifierOptions
            {
                Issuer = options.Issuer,
                ClientIds = new List<string>(options.ClientIds),
                JwksUri = options.JwksUri,
                CacheDuration = options.KeyCacheDuration,
                ClockSkew = options.ClockSkew,
                HttpClient = options.Backchannel,
            }))).Value;
        }

        public void Dispose()
        {
            foreach (var v in _verifiers.Values)
                if (v.IsValueCreated) v.Value.Dispose();
        }
    }

    /// <summary>Builds the <see cref="ClaimsPrincipal"/> of an app user.</summary>
    public static class AppUserPrincipal
    {
        public static ClaimsPrincipal Create(AppUser user, string authenticationType)
        {
            var issuer = user.Claims.TryGetProperty("iss", out var iss) ? iss.GetString() ?? ClaimsIdentity.DefaultIssuer : ClaimsIdentity.DefaultIssuer;
            var claims = new List<Claim>
            {
                new Claim(AppUserClaimTypes.Subject, user.Id, ClaimValueTypes.String, issuer),
                new Claim(ClaimTypes.NameIdentifier, user.Id, ClaimValueTypes.String, issuer),
                new Claim(AppUserClaimTypes.ClientId, user.ClientId, ClaimValueTypes.String, issuer),
                new Claim(AppUserClaimTypes.EmailVerified, user.EmailVerified ? "true" : "false", ClaimValueTypes.Boolean, issuer),
                new Claim(AppUserClaimTypes.Anonymous, user.Anonymous ? "true" : "false", ClaimValueTypes.Boolean, issuer),
            };
            if (user.PoolId != null) claims.Add(new Claim(AppUserClaimTypes.PoolId, user.PoolId, ClaimValueTypes.String, issuer));
            if (user.Email != null) claims.Add(new Claim(AppUserClaimTypes.Email, user.Email, ClaimValueTypes.String, issuer));
            if (user.OrgId != null) claims.Add(new Claim(AppUserClaimTypes.OrgId, user.OrgId, ClaimValueTypes.String, issuer));
            if (user.SessionId != null) claims.Add(new Claim(AppUserClaimTypes.SessionId, user.SessionId, ClaimValueTypes.String, issuer));
            foreach (var r in user.Roles) claims.Add(new Claim(AppUserClaimTypes.Role, r, ClaimValueTypes.String, issuer));
            foreach (var p in user.Permissions) claims.Add(new Claim(AppUserClaimTypes.Permission, p, ClaimValueTypes.String, issuer));
            foreach (var a in user.Amr) claims.Add(new Claim(AppUserClaimTypes.Amr, a, ClaimValueTypes.String, issuer));
            var identity = new ClaimsIdentity(claims, authenticationType, AppUserClaimTypes.Subject, AppUserClaimTypes.Role);
            return new ClaimsPrincipal(identity);
        }
    }

    public static class HttpContextAppUserExtensions
    {
        /// <summary>The verified app user of this request (null when the OpenBackAppAuth scheme did not authenticate it).</summary>
        public static AppUser? GetAppUser(this HttpContext context)
        {
            return context.Items.TryGetValue(OpenBackAppAuthDefaults.AppUserItemKey, out var user) ? user as AppUser : null;
        }
    }
}
