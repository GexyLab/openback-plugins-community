using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace OpenBack.AppAuth.AspNetCore
{
    public static class OpenBackAppAuthServiceCollectionExtensions
    {
        /// <summary>
        /// Adds authentication of the pool's access tokens as the DEFAULT scheme (<c>OpenBackAppAuth</c>), the authorization
        /// services and, unless <see cref="OpenBackAppAuthOptions.SetDefaultPolicy"/> is false, a default policy "an app user"
        /// (guests refused unless <see cref="OpenBackAppAuthOptions.AllowAnonymousUsers"/>).
        /// <code>
        /// builder.Services.AddOpenBackAppAuth(o =&gt;
        /// {
        ///     o.Issuer = "https://api.example.com/gateway/shop/auth/main";
        ///     o.ClientIds = new[] { "uapp_..." };
        /// });
        /// </code>
        /// Apps with other schemes (cookies...) use <c>services.AddAuthentication(...).AddOpenBackAppAuth(...)</c> instead.
        /// </summary>
        public static AuthenticationBuilder AddOpenBackAppAuth(this IServiceCollection services, Action<OpenBackAppAuthOptions> configure)
        {
            var builder = services.AddAuthentication(OpenBackAppAuthDefaults.AuthenticationScheme);
            builder.AddOpenBackAppAuth(OpenBackAppAuthDefaults.AuthenticationScheme, configure);
            return builder;
        }

        /// <summary>Adds the <c>OpenBackAppAuth</c> scheme to an authentication builder.</summary>
        public static AuthenticationBuilder AddOpenBackAppAuth(this AuthenticationBuilder builder, Action<OpenBackAppAuthOptions> configure)
        {
            return builder.AddOpenBackAppAuth(OpenBackAppAuthDefaults.AuthenticationScheme, configure);
        }

        /// <summary>Adds an app-user scheme named <paramref name="authenticationScheme"/> (e.g. one per pool).</summary>
        public static AuthenticationBuilder AddOpenBackAppAuth(this AuthenticationBuilder builder, string authenticationScheme,
            Action<OpenBackAppAuthOptions> configure)
        {
            if (configure == null) throw new ArgumentNullException(nameof(configure));
            var services = builder.Services;
            services.TryAddSingleton<OpenBackAppAuthVerifiers>();
            services.AddAuthorization();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, AppUserAuthorizationHandler>());
            services.AddOptions<AuthorizationOptions>().Configure<IOptionsMonitor<OpenBackAppAuthOptions>>((authz, monitor) =>
            {
                var o = monitor.Get(authenticationScheme);
                if (!o.SetDefaultPolicy) return;
                authz.DefaultPolicy = new AuthorizationPolicyBuilder(authenticationScheme)
                    .RequireAuthenticatedUser()
                    .AddRequirements(new AppUserRequirement(o.AllowAnonymousUsers, o.RequireVerifiedEmail, o.RequiredRoles, o.RequiredPermissions))
                    .Build();
            });
            return builder.AddScheme<OpenBackAppAuthOptions, OpenBackAppAuthHandler>(authenticationScheme, configure);
        }
    }
}
