using Microsoft.AspNetCore.Authentication.JwtBearer;
using ModelContextProtocol.AspNetCore.Authentication;
using ModelContextProtocol.Authentication;

var builder = WebApplication.CreateBuilder(args);

// The identity provider (MiniOidcServiceWeb) and this server's own canonical address.
// Tokens must be issued for `resource` (the client sends it as the OAuth "resource" parameter).
string authority = builder.Configuration["Authority"] ?? "http://localhost:5121";
string resource = builder.Configuration["Resource"] ?? "http://localhost:5046";

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        // Unauthenticated calls are challenged by the MCP handler, which returns 401 + a pointer to the resource metadata
        options.DefaultChallengeScheme = McpAuthenticationDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = resource;
        options.RequireHttpsMetadata = false;
        options.MapInboundClaims = false;
        options.RefreshInterval = TimeSpan.FromSeconds(5);
        options.TokenValidationParameters.RoleClaimType = "roles";
        options.TokenValidationParameters.NameClaimType = "name";
    })
    .AddMcp(options =>
    {
        // Served as RFC 9728 protected resource metadata: tells MCP clients which authorization server to use
        options.ResourceMetadata = new ProtectedResourceMetadata
        {
            Resource = resource,
            AuthorizationServers = { authority },
            ScopesSupported = ["mcp:tools"]
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
