// Alternative for server-rendered web apps: the STANDARD ASP.NET Core OpenID Connect handler pointed at the pool
// (Authority = the issuer). Register the app in the pool as kind "web" with the redirect URI
// https://<your host>/signin-oidc and the post-logout redirect URI https://<your host>/signout-callback-oidc.
//
//   set OpenBack__Issuer=https://api.example.com/gateway/shop/auth/main
//   set OpenBack__ClientId=uapp_...
//   dotnet user-secrets set OpenBack:ClientSecret <secret>      (never in source control)
//   dotnet run
//
// (OpenBack.AppAuth's OidcWebClient does the same flow by hand when you do not use this middleware.)
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["OpenBack:Issuer"] ?? "https://api.example.com/gateway/shop/auth/main";

builder.Services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(o =>
    {
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.SameSite = SameSiteMode.Lax;
    })
    .AddOpenIdConnect(o =>
    {
        o.Authority = issuer;                                   // discovery: <issuer>/.well-known/openid-configuration
        o.ClientId = builder.Configuration["OpenBack:ClientId"] ?? "uapp_example";
        o.ClientSecret = builder.Configuration["OpenBack:ClientSecret"];
        o.ResponseType = OpenIdConnectResponseType.Code;        // authorization code
        o.UsePkce = true;                                       // PKCE S256 (also with a secret)
        o.Scope.Clear();
        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.Scope.Add("email");
        o.MapInboundClaims = false;                             // keep "sub", "email", "roles" as they are
        o.TokenValidationParameters.NameClaimType = "name";
        o.TokenValidationParameters.RoleClaimType = "roles";
        o.SaveTokens = true;                                    // access/refresh tokens in the auth cookie (encrypted)
        o.GetClaimsFromUserInfoEndpoint = false;                // the ID token already carries the profile claims
        // Extras of the hosted page (provider, org_id, ui_locales...) go on the authorize request:
        o.Events.OnRedirectToIdentityProvider = ctx =>
        {
            if (ctx.Properties.Items.TryGetValue("provider", out var provider) && !string.IsNullOrEmpty(provider))
                ctx.ProtocolMessage.SetParameter("provider", provider);
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext ctx) => ctx.User.Identity?.IsAuthenticated == true
    ? Results.Text($"Hello {ctx.User.FindFirst("email")?.Value ?? ctx.User.FindFirst("sub")?.Value}. <a href=\"/logout\">Sign out</a>", "text/html")
    : Results.Text("<a href=\"/login\">Sign in</a>", "text/html"));

app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/" },
    new[] { OpenIdConnectDefaults.AuthenticationScheme }));

app.MapGet("/account", (HttpContext ctx) => new { sub = ctx.User.FindFirst("sub")?.Value, roles = ctx.User.FindAll("roles").Select(c => c.Value) })
    .RequireAuthorization();

app.MapGet("/logout", () => Results.SignOut(new AuthenticationProperties { RedirectUri = "/" },
    new[] { CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme }));

app.Run();
