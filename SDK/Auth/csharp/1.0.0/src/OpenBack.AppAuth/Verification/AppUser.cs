using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>The user behind a verified access token (<see cref="TokenVerifier.VerifyAsync"/>).</summary>
    public sealed class AppUser
    {
        /// <summary>The user id (<c>sub</c>, <c>usr_...</c>).</summary>
        public string Id { get; private set; } = "";
        /// <summary>The pool id (<c>pool</c>).</summary>
        public string? PoolId { get; private set; }
        /// <summary>The app the token was issued to (<c>aud</c>).</summary>
        public string ClientId { get; private set; } = "";
        public string? Email { get; private set; }
        public bool EmailVerified { get; private set; }
        /// <summary>True for guest accounts (<c>anon</c>).</summary>
        public bool Anonymous { get; private set; }
        /// <summary>The active organization (<c>org_id</c>); B2C pools have a hidden one.</summary>
        public string? OrgId { get; private set; }
        public IReadOnlyList<string> Roles { get; private set; } = Array.Empty<string>();
        /// <summary>The permissions in the active organization; <c>*</c> means all.</summary>
        public IReadOnlyList<string> Permissions { get; private set; } = Array.Empty<string>();
        /// <summary>The custom attributes (<c>attr</c>).</summary>
        public IReadOnlyDictionary<string, JsonElement> Attributes { get; private set; } = new Dictionary<string, JsonElement>();
        /// <summary>The session (<c>sid</c>).</summary>
        public string? SessionId { get; private set; }
        /// <summary>How the user signed in: <c>pwd</c>, <c>email</c>, <c>anon</c>, <c>fed</c>, <c>otp</c>, <c>recovery</c>, <c>mfa</c>.</summary>
        public IReadOnlyList<string> Amr { get; private set; } = Array.Empty<string>();
        public string? Scope { get; private set; }
        public DateTimeOffset ExpiresAt { get; private set; }
        /// <summary>All the claims of the token.</summary>
        public JsonElement Claims { get; private set; }

        public bool HasRole(string role) => Roles.Contains(role, StringComparer.Ordinal);

        /// <summary>True when <see cref="Permissions"/> contains <paramref name="permission"/> or <c>*</c>.</summary>
        public bool HasPermission(string permission) =>
            Permissions.Contains("*", StringComparer.Ordinal) || Permissions.Contains(permission, StringComparer.Ordinal);

        internal static AppUser From(JsonElement claims, string clientId)
        {
            var attributes = new Dictionary<string, JsonElement>();
            if (claims.TryGetProperty("attr", out var attr) && attr.ValueKind == JsonValueKind.Object)
                foreach (var p in attr.EnumerateObject()) attributes[p.Name] = p.Value.Clone();
            return new AppUser
            {
                Id = Json.Str(claims, "sub") ?? "",
                PoolId = Json.Str(claims, "pool"),
                ClientId = clientId,
                Email = Json.Str(claims, "email"),
                EmailVerified = Json.Bool(claims, "email_verified"),
                Anonymous = Json.Bool(claims, "anon"),
                OrgId = Json.Str(claims, "org_id"),
                Roles = Json.StrList(claims, "roles"),
                Permissions = Json.StrList(claims, "permissions"),
                Attributes = attributes,
                SessionId = Json.Str(claims, "sid"),
                Amr = Json.StrList(claims, "amr"),
                Scope = Json.Str(claims, "scope"),
                ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(Json.Num(claims, "exp") ?? 0),
                Claims = claims,
            };
        }

        public override string ToString() => $"AppUser({Id})";
    }
}
