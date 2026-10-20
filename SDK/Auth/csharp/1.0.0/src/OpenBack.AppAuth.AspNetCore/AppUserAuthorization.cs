using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace OpenBack.AppAuth.AspNetCore
{
    /// <summary>"An app user of the pool" with optional conditions. Guests (<c>anon</c>) are refused unless
    /// <see cref="AllowAnonymous"/>.</summary>
    public sealed class AppUserRequirement : IAuthorizationRequirement
    {
        public AppUserRequirement(bool allowAnonymous = false, bool requireVerifiedEmail = false,
            IEnumerable<string>? anyOfRoles = null, IEnumerable<string>? allPermissions = null)
        {
            AllowAnonymous = allowAnonymous;
            RequireVerifiedEmail = requireVerifiedEmail;
            AnyOfRoles = (anyOfRoles ?? Array.Empty<string>()).ToArray();
            AllPermissions = (allPermissions ?? Array.Empty<string>()).ToArray();
        }

        public bool AllowAnonymous { get; }
        public bool RequireVerifiedEmail { get; }
        /// <summary>At least one of these roles (empty: no check).</summary>
        public IReadOnlyList<string> AnyOfRoles { get; }
        /// <summary>All these permissions (empty: no check; <c>*</c> grants all).</summary>
        public IReadOnlyList<string> AllPermissions { get; }
    }

    /// <summary>Evaluates <see cref="AppUserRequirement"/> on the claims built by <see cref="AppUserPrincipal"/>.</summary>
    public sealed class AppUserAuthorizationHandler : AuthorizationHandler<AppUserRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AppUserRequirement requirement)
        {
            var identity = context.User.Identities.FirstOrDefault(i => i.IsAuthenticated
                && i.HasClaim(c => c.Type == AppUserClaimTypes.PoolId) && i.HasClaim(c => c.Type == AppUserClaimTypes.Subject));
            if (identity == null) return Task.CompletedTask;
            if (!requirement.AllowAnonymous && identity.HasClaim(AppUserClaimTypes.Anonymous, "true")) return Task.CompletedTask;
            if (requirement.RequireVerifiedEmail && !identity.HasClaim(AppUserClaimTypes.EmailVerified, "true")) return Task.CompletedTask;
            if (requirement.AnyOfRoles.Count > 0 && !requirement.AnyOfRoles.Any(r => identity.HasClaim(AppUserClaimTypes.Role, r)))
                return Task.CompletedTask;
            if (requirement.AllPermissions.Count > 0 && !identity.HasClaim(AppUserClaimTypes.Permission, "*")
                && !requirement.AllPermissions.All(p => identity.HasClaim(AppUserClaimTypes.Permission, p)))
                return Task.CompletedTask;
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }

    /// <summary>Policy helpers. Each one refuses guest accounts unless stated.
    /// <code>
    /// builder.Services.AddAuthorization(o =&gt;
    /// {
    ///     o.AddAppUserPolicy("admins", p =&gt; p.RequireAppRole("admin", "owner"));
    ///     o.AddAppUserPolicy("invoices", p =&gt; p.RequireAppPermission("invoices.read"));
    ///     o.AddAppUserPolicy("guests-ok", p =&gt; p.RequireAppUser(allowAnonymous: true));
    /// });
    /// </code></summary>
    public static class AppUserPolicyExtensions
    {
        /// <summary>An app user (guests only with <paramref name="allowAnonymous"/>; optionally with a verified email).</summary>
        public static AuthorizationPolicyBuilder RequireAppUser(this AuthorizationPolicyBuilder policy, bool allowAnonymous = false,
            bool requireVerifiedEmail = false)
        {
            return policy.RequireAuthenticatedUser().AddRequirements(new AppUserRequirement(allowAnonymous, requireVerifiedEmail));
        }

        /// <summary>An app user, guest accounts included.</summary>
        public static AuthorizationPolicyBuilder RequireAppUserOrGuest(this AuthorizationPolicyBuilder policy)
        {
            return policy.RequireAppUser(allowAnonymous: true);
        }

        /// <summary>An app user with at least one of <paramref name="roles"/> (in the active organization).</summary>
        public static AuthorizationPolicyBuilder RequireAppRole(this AuthorizationPolicyBuilder policy, params string[] roles)
        {
            return policy.RequireAuthenticatedUser().AddRequirements(new AppUserRequirement(anyOfRoles: roles));
        }

        /// <summary>An app user with all <paramref name="permissions"/> (<c>*</c> grants all).</summary>
        public static AuthorizationPolicyBuilder RequireAppPermission(this AuthorizationPolicyBuilder policy, params string[] permissions)
        {
            return policy.RequireAuthenticatedUser().AddRequirements(new AppUserRequirement(allPermissions: permissions));
        }

        /// <summary>An app user whose email is verified.</summary>
        public static AuthorizationPolicyBuilder RequireVerifiedAppEmail(this AuthorizationPolicyBuilder policy)
        {
            return policy.RequireAppUser(requireVerifiedEmail: true);
        }

        /// <summary>Adds a named policy authenticated by the OpenBackAppAuth scheme (<paramref name="authenticationScheme"/>).</summary>
        public static AuthorizationOptions AddAppUserPolicy(this AuthorizationOptions options, string name,
            Action<AuthorizationPolicyBuilder> configure, string authenticationScheme = OpenBackAppAuthDefaults.AuthenticationScheme)
        {
            var builder = new AuthorizationPolicyBuilder(authenticationScheme);
            configure(builder);
            options.AddPolicy(name, builder.Build());
            return options;
        }
    }
}
