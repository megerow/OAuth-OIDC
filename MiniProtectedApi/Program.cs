using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Which identity provider to trust comes from the "Auth" section of appsettings.json,
// so switching providers (for example to Entra ID or Okta) is a configuration change.
var auth = builder.Configuration.GetSection("Auth").Get<AuthSettings>() ?? new AuthSettings();
if (string.IsNullOrWhiteSpace(auth.Authority) || string.IsNullOrWhiteSpace(auth.Audience))
{
    throw new InvalidOperationException("Auth:Authority and Auth:Audience must be set (see appsettings.json).");
}

// 1. Register JWT Bearer Authentication Middleware
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = auth.Authority;
        options.Audience = auth.Audience;
        options.RequireHttpsMetadata = auth.RequireHttpsMetadata;

        // Keep claim names as issued; otherwise "roles" is renamed to the long ClaimTypes.Role URI and the role claim below matches nothing
        options.MapInboundClaims = false;

        // Only for providers that rotate their signing key often (the mock IdP does on every restart); the default throttle is 5 minutes
        if (auth.MetadataRefreshSeconds is > 0)
        {
            options.RefreshInterval = TimeSpan.FromSeconds(auth.MetadataRefreshSeconds.Value);
        }

        // Map the token's role claim to the standard .NET User.IsInRole() system
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            RoleClaimType = auth.RoleClaimType
        };
    });

// 2. Enable Authorization Engines
builder.Services.AddAuthorization();

var app = builder.Build();

// Enable the security pipelines
app.UseAuthentication();
app.UseAuthorization();

// 3. Public Endpoint
app.MapGet("/api/public", () => "Hello! Anyone can see this public data.");

// 4. Secure Endpoint - Requires a valid token AND the "Admin" role
app.MapGet("/api/admin-dashboard", [Authorize(Roles = "Admin")] () => 
    new { message = "Welcome to the Admin Dashboard! Your custom OIDC roles successfully allowed access." });

// 5. Secure Endpoint - Requires the "BillingManager" role
app.MapGet("/api/billing", [Authorize(Roles = "BillingManager")] () => 
    new { message = "Access Granted: Secure Financial Reporting System." });

app.Run();

class AuthSettings
{
    public string Authority { get; set; } = "";
    public string Audience { get; set; } = "";
    public string RoleClaimType { get; set; } = "roles";
    public bool RequireHttpsMetadata { get; set; } = true;
    public int? MetadataRefreshSeconds { get; set; }
}
