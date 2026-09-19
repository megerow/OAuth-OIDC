using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// 1. Register JWT Bearer Authentication Middleware
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        // Point this directly to your custom Identity Provider
        options.Authority = builder.Configuration["Authority"] ?? "http://localhost:5121";
        options.Audience = "my_learning_client_app";
        
        // Since we are running locally without real SSL certificates, turn off HTTPS requirements
        options.RequireHttpsMetadata = false;

        // Keep claim names as issued; otherwise "roles" is renamed to the long ClaimTypes.Role URI and RoleClaimType = "roles" matches nothing
        options.MapInboundClaims = false;

        // The mock IdP generates a new signing key on every restart; refetch keys quickly (default throttle is 5 minutes)
        options.RefreshInterval = TimeSpan.FromSeconds(5);

        // Map the OIDC "roles" claim to the standard .NET User.IsInRole() system
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            RoleClaimType = "roles" 
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
