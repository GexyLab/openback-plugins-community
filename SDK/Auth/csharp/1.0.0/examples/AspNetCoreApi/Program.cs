// An ASP.NET Core minimal API protected by the access tokens of an OpenBack user pool.
// Tokens are verified locally (ES256, the pool's JWKS): no call to OpenBack per request.
//
//   set OpenBack__Issuer=https://api.example.com/gateway/shop/auth/main
//   set OpenBack__ClientId=uapp_...
//   dotnet run
//   curl -H "Authorization: Bearer <access token>" http://localhost:5000/me
using OpenBack.AppAuth;
using OpenBack.AppAuth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenBackAppAuth(o =>
{
    o.Issuer = builder.Configuration["OpenBack:Issuer"] ?? "https://api.example.com/gateway/shop/auth/main";
    o.ClientIds = new[] { builder.Configuration["OpenBack:ClientId"] ?? "uapp_example" };
    // The default policy ([Authorize], RequireAuthorization()) refuses guest accounts; set true to accept them:
    o.AllowAnonymousUsers = false;
});
builder.Services.AddAuthorization(o =>
{
    o.AddAppUserPolicy("admins", p => p.RequireAppRole("admin", "owner"));
    o.AddAppUserPolicy("orders.read", p => p.RequireAppPermission("orders.read"));
    o.AddAppUserPolicy("verified", p => p.RequireVerifiedAppEmail());
    o.AddAppUserPolicy("anyone-signed-in", p => p.RequireAppUserOrGuest());
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "public");

// Any signed-in (non-guest) user. 401 {"error":"invalid_token"} without a valid token.
app.MapGet("/me", (HttpContext ctx) =>
{
    AppUser user = ctx.GetAppUser()!;
    return new { user.Id, user.Email, user.OrgId, user.Roles, user.Permissions };
}).RequireAuthorization();

// 403 {"error":"insufficient_scope"} when the policy refuses.
app.MapGet("/admin/stats", () => new { users = 42 }).RequireAuthorization("admins");
app.MapGet("/orders", (HttpContext ctx) => new[] { new { id = 1, owner = ctx.User.FindFirst("sub")!.Value } }).RequireAuthorization("orders.read");
app.MapGet("/billing", () => "ok").RequireAuthorization("verified");
app.MapGet("/cart", () => "guests welcome").RequireAuthorization("anyone-signed-in");

app.Run();
