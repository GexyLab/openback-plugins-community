using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace OpenBack.AppAuth.AspNetCore
{
    public static class OpenBackAppAuthDefaults
    {
        /// <summary>The default authentication scheme name: <c>OpenBackAppAuth</c>.</summary>
        public const string AuthenticationScheme = "OpenBackAppAuth";

        /// <summary>The <see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/> key of the verified <see cref="AppUser"/>.</summary>
        public const string AppUserItemKey = "OpenBack.AppAuth.AppUser";
    }

    /// <summary>The claim types of the principal built from an app user's access token.</summary>
    public static class AppUserClaimTypes
    {
        public const string Subject = "sub";
        public const string Email = "email";
        public const string EmailVerified = "email_verified";
        /// <summary>Roles use the standard role claim type, so <c>User.IsInRole("admin")</c> and <c>[Authorize(Roles = ...)]</c> work.</summary>
        public const string Role = ClaimTypes.Role;
        public const string Permission = "permission";
        public const string OrgId = "org_id";
        public const string PoolId = "pool";
        public const string ClientId = "client_id";
        public const string SessionId = "sid";
        public const string Anonymous = "anon";
        public const string Amr = "amr";
    }

    /// <summary>Options of the <c>OpenBackAppAuth</c> authentication scheme.</summary>
    public sealed class OpenBackAppAuthOptions : AuthenticationSchemeOptions
    {
        /// <summary>The pool's address (the tokens' <c>iss</c>), e.g. <c>https://api.example.com/gateway/shop/auth/main</c>.</summary>
        public string Issuer { get; set; } = "";

        /// <summary>The client IDs whose tokens are accepted (<c>aud</c>).</summary>
        public IList<string> ClientIds { get; set; } = new List<string>();

        /// <summary>Default <c>&lt;issuer&gt;/.well-known/jwks.json</c>.</summary>
        public string? JwksUri { get; set; }

        /// <summary>How long the pool's keys are cached (default 10 minutes).</summary>
        public TimeSpan KeyCacheDuration { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>Tolerance on the token's times (default 60 s).</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>The HTTP client used to read the keys (default: a new one).</summary>
        public HttpClient? Backchannel { get; set; }

        /// <summary>When true (default), the default authorization policy (<c>[Authorize]</c>, <c>RequireAuthorization()</c>)
        /// becomes "an app user of this scheme" with <see cref="AllowAnonymousUsers"/> and <see cref="RequireVerifiedEmail"/>.</summary>
        public bool SetDefaultPolicy { get; set; } = true;

        /// <summary>Default policy: accept guest accounts (<c>anon: true</c>)? Default false (403).</summary>
        public bool AllowAnonymousUsers { get; set; }

        /// <summary>Default policy: require a verified email? Default false.</summary>
        public bool RequireVerifiedEmail { get; set; }

        /// <summary>Default policy: the user must have one of these roles (empty: no check).</summary>
        public IList<string> RequiredRoles { get; set; } = new List<string>();

        /// <summary>Default policy: the user must have all these permissions (empty: no check; <c>*</c> grants all).</summary>
        public IList<string> RequiredPermissions { get; set; } = new List<string>();

        public override void Validate()
        {
            base.Validate();
            if (string.IsNullOrWhiteSpace(Issuer)) throw new ArgumentException("OpenBackAppAuthOptions.Issuer is required.");
            if (ClientIds == null || ClientIds.Count == 0) throw new ArgumentException("OpenBackAppAuthOptions.ClientIds needs at least one client ID.");
        }
    }
}
