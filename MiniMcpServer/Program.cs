using Microsoft.AspNetCore.Authentication.JwtBearer;
using ModelContextProtocol.AspNetCore.Authentication;
using ModelContextProtocol.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Which identity provider to trust comes from the "Auth" section of appsettings.json,
// so switching providers (for example to Entra ID or Okta) is a configuration change.
var auth = builder.Configuration.GetSection("Auth").Get<AuthSettings>() ?? new AuthSettings();
if (string.IsNullOrWhiteSpace(auth.Authority) || string.IsNullOrWhiteSpace(auth.Audience))
{
    throw new InvalidOperationException("Auth:Authority and Auth:Audience must be set (see appsettings.json).");
}

string authority = auth.Authority;

// Audience is what tokens must be issued for. Resource is this server's own address, published to MCP clients.
// With the mock IdP they are the same; with Entra ID the audience is usually an app ID URI instead.
string resource = string.IsNullOrWhiteSpace(auth.Resource) ? auth.Audience : auth.Resource;

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        // Unauthenticated calls are challenged by the MCP handler, which returns 401 + a pointer to the resource metadata
        options.DefaultChallengeScheme = McpAuthenticationDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = auth.Audience;
        options.RequireHttpsMetadata = auth.RequireHttpsMetadata;
        options.MapInboundClaims = false;

        // Only for providers that rotate their signing key often (the mock IdP does on every restart); the default throttle is 5 minutes
        if (auth.MetadataRefreshSeconds is > 0)
        {
            options.RefreshInterval = TimeSpan.FromSeconds(auth.MetadataRefreshSeconds.Value);
        }

        options.TokenValidationParameters.RoleClaimType = auth.RoleClaimType;
        options.TokenValidationParameters.NameClaimType = "name";
    })
    .AddMcp(options =>
    {
        // Served as RFC 9728 protected resource metadata: tells MCP clients which authorization server to use
        options.ResourceMetadata = new ProtectedResourceMetadata
        {
            Resource = resource,
            AuthorizationServers = { authority },
            ScopesSupported = auth.Scopes.ToList()
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();

builder.Services.AddMcpServer()
    .WithHttpTransport()
    .WithTools<DemoTools>()
    .AddAuthorizationFilters(); // enforces [Authorize] on tools and hides tools the caller may not use

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapMcp("/mcp").RequireAuthorization();

app.Run();

class AuthSettings
{
    public string Authority { get; set; } = "";
    public string Audience { get; set; } = "";
    public string Resource { get; set; } = "";
    public string[] Scopes { get; set; } = [];
    public string RoleClaimType { get; set; } = "roles";
    public bool RequireHttpsMetadata { get; set; } = true;
    public int? MetadataRefreshSeconds { get; set; }
}
