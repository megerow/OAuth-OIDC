using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// 1. Core State
using RSA rsaKey = RSA.Create(2048);

// Key ID derived from the public key, so a restart (new key) never reuses a stale kid
var publicParams = rsaKey.ExportParameters(false);
string kid = Base64UrlEncode(SHA256.HashData(publicParams.Modulus!))[..16];

string IssuerFor(HttpRequest r) => $"{r.Scheme}://{r.Host}";
string Html(string? s) => WebUtility.HtmlEncode(s ?? "");

// Active login flows in progress (maps: temporary auth_code -> session details)
var activeFlows = new ConcurrentDictionary<string, AuthFlowSession>();

// Refresh tokens live only here, keyed by the opaque token string. Used tokens stay until they expire so a replay can be recognised.
var refreshTokens = new ConcurrentDictionary<string, RefreshRecord>();
object refreshLock = new();

int accessTokenSeconds = Math.Max(1, app.Configuration.GetValue<int>("Tokens:AccessTokenSeconds", 3600));
int refreshTokenSeconds = Math.Max(1, app.Configuration.GetValue<int>("Tokens:RefreshTokenSeconds", 86400));

// Registered clients (static + dynamically registered via /register): client_id -> exact redirect URIs allowed
var registeredClients = new ConcurrentDictionary<string, HashSet<string>>
{
    ["my_learning_client_app"] = new() { "http://localhost:8080/callback/" }
};

// Mock User Database with Roles
var mockUserDatabase = new Dictionary<string, (string Password, string Name, string[] Roles)>
{
    { "jane.doe@example.com", ("password123", "Jane Doe", new[] { "Admin", "BillingManager" }) },
    { "john.smith@example.com", ("password123", "John Smith", new[] { "BillingManager" }) }
};

// Authorization server metadata, served both as OIDC discovery and as RFC 8414 metadata (MCP clients look for either)
object ServerMetadata(string issuer) => new
{
    issuer,
    authorization_endpoint = $"{issuer}/authorize",
    token_endpoint = $"{issuer}/token",
    jwks_uri = $"{issuer}/.well-known/jwks.json",
    registration_endpoint = $"{issuer}/register",
    response_types_supported = new[] { "code" },
    grant_types_supported = new[] { "authorization_code", "refresh_token" },
    subject_types_supported = new[] { "public" },
    id_token_signing_alg_values_supported = new[] { "RS256" },
    code_challenge_methods_supported = new[] { "S256" },
    token_endpoint_auth_methods_supported = new[] { "none" },
    scopes_supported = new[] { "openid", "offline_access", "mcp:tools" }
};

app.MapGet("/.well-known/openid-configuration", (HttpRequest request) => Results.Json(ServerMetadata(IssuerFor(request))));
app.MapGet("/.well-known/oauth-authorization-server", (HttpRequest request) => Results.Json(ServerMetadata(IssuerFor(request))));

// Public signing key (JWK) used to verify the RS256 signature on issued tokens
app.MapGet("/.well-known/jwks.json", () => Results.Json(new
{
    keys = new[]
    {
        new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid,
            n = Base64UrlEncode(publicParams.Modulus!),
            e = Base64UrlEncode(publicParams.Exponent!)
        }
    }
}));

// Dynamic Client Registration (RFC 7591): public clients register their redirect URIs and receive a client_id
app.MapPost("/register", async (HttpContext context) =>
{
    JsonElement body;
    try
    {
        body = (await JsonDocument.ParseAsync(context.Request.Body)).RootElement;
    }
    catch (JsonException)
    {
        return Results.Json(new { error = "invalid_client_metadata", error_description = "Body must be JSON" }, statusCode: 400);
    }

    if (body.ValueKind != JsonValueKind.Object ||
        !body.TryGetProperty("redirect_uris", out var uris) || uris.ValueKind != JsonValueKind.Array || uris.GetArrayLength() == 0)
    {
        return Results.Json(new { error = "invalid_redirect_uri", error_description = "redirect_uris is required" }, statusCode: 400);
    }

    var redirectUris = new HashSet<string>();
    foreach (var element in uris.EnumerateArray())
    {
        string? uri = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
        if (!IsAcceptableRedirectUri(uri))
        {
            return Results.Json(new { error = "invalid_redirect_uri", error_description = "Redirect URIs must be absolute https URIs or http loopback URIs, without fragments" }, statusCode: 400);
        }
        redirectUris.Add(uri!);
    }

    string clientId = "client_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    registeredClients[clientId] = redirectUris;

    string? clientName = body.TryGetProperty("client_name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String ? nameElement.GetString() : null;

    return Results.Json(new
    {
        client_id = clientId,
        client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        client_name = clientName,
        redirect_uris = redirectUris,
        token_endpoint_auth_method = "none",
        grant_types = new[] { "authorization_code", "refresh_token" },
        response_types = new[] { "code" }
    }, statusCode: 201);
});

// 2. Endpoint: The Initial OIDC Redirection Trigger (Step 1 & 2 of the Flow)
app.MapGet("/authorize", ([FromQuery] string client_id, [FromQuery] string redirect_uri, [FromQuery] string code_challenge, [FromQuery] string code_challenge_method,
    [FromQuery] string? resource, [FromQuery] string? scope, [FromQuery] string? state) =>
{
    var error = ValidateAuthorizationRequest(client_id, redirect_uri, code_challenge_method, resource);
    if (error != null)
    {
        return error;
    }

    // Prefilled with the demo user so a first-time visitor can just click the button
    return LoginForm(client_id, redirect_uri, code_challenge, code_challenge_method, resource, scope, state, "jane.doe@example.com", "password123", null);
});

// A lightweight, raw HTML login/consent form. It is also shown again, with an error, when a sign-in fails.
IResult LoginForm(string clientId, string redirectUri, string codeChallenge, string codeChallengeMethod, string? resource, string? scope, string? state, string email, string password, string? errorMessage)
{
    string errorHtml = errorMessage == null
        ? ""
        : $"<p role='alert' style='color:#a4262c; background:#fde7e9; border:1px solid #a4262c; padding:8px 12px; border-radius:4px;'>{Html(errorMessage)}</p>";

    var html = $@"
        <html>
        <body style='font-family: sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px;'>
            <h2>Login to Identity Provider</h2>
            {errorHtml}
            <form action='/login' method='POST'>
                <!-- Pass along the client parameters hidden so the form submission keeps context -->
                <input type='hidden' name='client_id' value='{Html(clientId)}' />
                <input type='hidden' name='redirect_uri' value='{Html(redirectUri)}' />
                <input type='hidden' name='code_challenge' value='{Html(codeChallenge)}' />
                <input type='hidden' name='code_challenge_method' value='{Html(codeChallengeMethod)}' />
                <input type='hidden' name='resource' value='{Html(resource)}' />
                <input type='hidden' name='scope' value='{Html(scope)}' />
                <input type='hidden' name='state' value='{Html(state)}' />

                <div style='margin-bottom:15px;'>
                    <label>Email:</label><br/>
                    <input type='email' name='email' value='{Html(email)}' style='width:100%; padding:8px;' required />
                </div>
                <div style='margin-bottom:15px;'>
                    <label>Password:</label><br/>
                    <input type='password' name='password' value='{Html(password)}' style='width:100%; padding:8px;' required />
                </div>
                <button type='submit' style='width:100%; padding:10px; background-color:#0078d4; color:white; border:none; border-radius:4px; font-weight:bold;'>
                    Sign In & Grant Consent
                </button>
            </form>
        </body>
        </html>";

    return Results.Content(html, "text/html");
}

// 3. Endpoint: Form Post-Back Process (Step 3 & 4 of the Flow)
app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string email = form["email"].ToString();
    string password = form["password"].ToString();
    string clientId = form["client_id"].ToString();
    string redirectUri = form["redirect_uri"].ToString();
    string codeChallenge = form["code_challenge"].ToString();
    string? resource = NullIfEmpty(form["resource"].ToString());
    string? scope = NullIfEmpty(form["scope"].ToString());
    string? state = NullIfEmpty(form["state"].ToString());

    // The form fields are attacker-controllable, so the request is validated again here, not just at /authorize
    var error = ValidateAuthorizationRequest(clientId, redirectUri, form["code_challenge_method"].ToString(), resource);
    if (error != null || string.IsNullOrEmpty(codeChallenge))
    {
        return error ?? Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge is required" });
    }

    // Validate Credentials. A wrong password shows the form again with a generic message (no hint about which part was wrong)
    // and keeps the request details, so the user can retry. The password is never echoed back.
    if (!mockUserDatabase.TryGetValue(email, out var userRecord) || userRecord.Password != password)
    {
        return LoginForm(clientId, redirectUri, codeChallenge, form["code_challenge_method"].ToString(), resource, scope, state, email, "", "Incorrect email or password.");
    }

    // Generate a secure, randomized one-time authorization code
    string authorizationCode = "auth_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    // Save the workflow data in memory to match up during the subsequent /token exchange
    activeFlows[authorizationCode] = new AuthFlowSession(clientId, redirectUri, codeChallenge, email, userRecord.Name, userRecord.Roles, resource, scope);

    // Redirect the browser window straight back to the client application with the code (and the client's state, if any)
    var callbackParams = new Dictionary<string, string?> { ["code"] = authorizationCode };
    if (state != null)
    {
        callbackParams["state"] = state;
    }
    return Results.Redirect(QueryHelpers.AddQueryString(redirectUri, callbackParams));
});

// 4. Endpoint: /token. Two grants: authorization_code (Steps 5-7 of the flow) and refresh_token.
app.MapPost("/token", async (HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";

    var form = await context.Request.ReadFormAsync();
    return form["grant_type"].ToString() switch
    {
        "" or "authorization_code" => ExchangeAuthorizationCode(context, form),
        "refresh_token" => ExchangeRefreshToken(context, form),
        _ => TokenError("unsupported_grant_type", "Supported grants: authorization_code, refresh_token")
    };
});

IResult TokenError(string error, string description) =>
    Results.Json(new { error, error_description = description }, statusCode: StatusCodes.Status400BadRequest);

string[] SplitScopes(string? scope) =>
    string.IsNullOrWhiteSpace(scope) ? [] : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

IResult ExchangeAuthorizationCode(HttpContext context, IFormCollection form)
{
    string? code = form["code"];
    string? codeVerifier = form["code_verifier"];

    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(codeVerifier))
    {
        return TokenError("invalid_request", "code and code_verifier are required");
    }

    if (!activeFlows.TryGetValue(code, out var session))
    {
        return TokenError("invalid_grant", "Code not found");
    }

    // PKCE Verification
    using var sha256 = SHA256.Create();
    string computedChallenge = Base64UrlEncode(sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier)));

    if (computedChallenge != session.CodeChallenge)
    {
        return TokenError("invalid_grant", "PKCE verification failed");
    }

    // If the client repeats these parameters at the token endpoint, they must match the authorization request
    string? tokenClientId = NullIfEmpty(form["client_id"].ToString());
    string? tokenRedirectUri = NullIfEmpty(form["redirect_uri"].ToString());
    string? tokenResource = NullIfEmpty(form["resource"].ToString());

    if ((tokenClientId != null && tokenClientId != session.ClientId) || (tokenRedirectUri != null && tokenRedirectUri != session.RedirectUri))
    {
        return TokenError("invalid_grant", "client_id or redirect_uri does not match the authorization request");
    }

    if (tokenResource != null && session.Resource != null && tokenResource != session.Resource)
    {
        return TokenError("invalid_target", "resource does not match the authorization request");
    }

    // Burn the code immediately so it's strictly single-use
    activeFlows.TryRemove(code, out _);

    // Every refresh token issued from this login shares a family id, so a replayed one can revoke them all
    return IssueTokens(context, session, Base64UrlEncode(RandomNumberGenerator.GetBytes(12)), null, tokenResource);
}

// Refresh grant (RFC 6749 section 6). Each refresh token works once: using it returns a new one in the same family.
// Presenting one that was already used means it leaked, so the whole family is revoked (the OAuth security BCP's advice, and what Okta does).
IResult ExchangeRefreshToken(HttpContext context, IFormCollection form)
{
    string presented = form["refresh_token"].ToString();
    string? clientId = NullIfEmpty(form["client_id"].ToString());
    string? requestedScope = NullIfEmpty(form["scope"].ToString());
    string? tokenResource = NullIfEmpty(form["resource"].ToString());

    if (presented == "" || clientId == null)
    {
        return TokenError("invalid_request", "refresh_token and client_id are required");
    }

    // One message for every way a refresh token can be unusable, so a caller learns nothing about which tokens exist
    IResult invalid = TokenError("invalid_grant", "The refresh token is invalid, expired or revoked");

    AuthFlowSession original;
    string familyId;
    lock (refreshLock)
    {
        if (!refreshTokens.TryGetValue(presented, out var record))
        {
            return invalid;
        }

        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            refreshTokens.TryRemove(presented, out _);
            return invalid;
        }

        if (record.Session.ClientId != clientId)
        {
            return invalid;
        }

        if (record.Used)
        {
            RevokeFamily(record.FamilyId);
            app.Logger.LogWarning("Refresh token reuse detected for {Account}: revoked all refresh tokens from that sign-in", record.Session.UserEmail);
            return invalid;
        }

        // A refresh may ask for fewer scopes than were granted, never more
        if (requestedScope != null && !SplitScopes(requestedScope).All(SplitScopes(record.Session.Scope).Contains))
        {
            return TokenError("invalid_scope", "The requested scope exceeds the scope originally granted");
        }

        if (tokenResource != null && record.Session.Resource != null && tokenResource != record.Session.Resource)
        {
            return TokenError("invalid_target", "resource does not match the original authorization");
        }

        record.Used = true;
        original = record.Session;
        familyId = record.FamilyId;
    }

    var current = ReevaluateSession(original);
    if (current == null)
    {
        RevokeFamily(familyId);
        return invalid;
    }

    return IssueTokens(context, current, familyId, requestedScope, tokenResource);
}

// Looks the user up again at every refresh, so a user who no longer exists cannot keep refreshing.
AuthFlowSession? ReevaluateSession(AuthFlowSession session) =>
    mockUserDatabase.TryGetValue(session.UserEmail, out var user)
        ? session with { UserName = user.Name, UserRoles = user.Roles }
        : null;

// Builds the token response for either grant
IResult IssueTokens(HttpContext context, AuthFlowSession session, string familyId, string? narrowedScope, string? tokenResource)
{
    string issuer = IssuerFor(context.Request);

    // The access token is audience-bound to the protected resource the client asked for (RFC 8707); with no resource it falls back to the client
    string audience = session.Resource ?? tokenResource ?? session.ClientId;

    // offline_access only asks for a refresh token. Like Entra ID, keep it out of the access token's own scope list.
    string[] granted = SplitScopes(narrowedScope ?? session.Scope);
    string[] apiScopes = granted.Where(s => s != "offline_access").ToArray();

    var accessTokenClaims = new Dictionary<string, object> { ["client_id"] = session.ClientId };
    if (apiScopes.Length > 0)
    {
        accessTokenClaims["scope"] = string.Join(' ', apiScopes);
    }
    string accessToken = GenerateJwtToken(rsaKey, issuer, audience, session.UserEmail, session.UserName, session.UserRoles, accessTokenClaims);

    // The id_token is for the client itself, so its audience is always the client_id
    string idToken = GenerateJwtToken(rsaKey, issuer, session.ClientId, session.UserEmail, session.UserName, session.UserRoles);

    var response = new Dictionary<string, object>
    {
        ["access_token"] = accessToken,
        ["token_type"] = "Bearer",
        ["expires_in"] = accessTokenSeconds,
        ["id_token"] = idToken
    };
    if (granted.Length > 0)
    {
        response["scope"] = string.Join(' ', granted);
    }

    // As with Entra ID and Okta, a refresh token is only issued when the client asked for the offline_access scope
    if (SplitScopes(session.Scope).Contains("offline_access"))
    {
        response["refresh_token"] = NewRefreshToken(session, familyId);
    }

    return Results.Json(response);
}

string NewRefreshToken(AuthFlowSession session, string familyId)
{
    var now = DateTimeOffset.UtcNow;
    foreach (var expired in refreshTokens.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList())
    {
        refreshTokens.TryRemove(expired, out _);
    }

    // An opaque random string: the client cannot read it, and only this IdP knows what it stands for.
    // Its lifetime slides: every refresh hands out a new token with a fresh full lifetime.
    string token = "rt_" + Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    refreshTokens[token] = new RefreshRecord(session, familyId, now.AddSeconds(refreshTokenSeconds));
    return token;
}

void RevokeFamily(string familyId)
{
    foreach (var key in refreshTokens.Where(kv => kv.Value.FamilyId == familyId).Select(kv => kv.Key).ToList())
    {
        refreshTokens.TryRemove(key, out _);
    }
}

IResult? ValidateAuthorizationRequest(string clientId, string redirectUri, string codeChallengeMethod, string? resource)
{
    // Unknown client or unregistered redirect: never redirect back, since that would be an open redirect
    if (!registeredClients.TryGetValue(clientId, out var allowedRedirects) || !allowedRedirects.Contains(redirectUri))
    {
        return Results.BadRequest(new { error = "invalid_request", error_description = "Unknown client_id or unregistered redirect_uri" });
    }

    if (codeChallengeMethod != "S256")
    {
        return Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge_method must be S256" });
    }

    if (resource != null && !Uri.TryCreate(resource, UriKind.Absolute, out _))
    {
        return Results.BadRequest(new { error = "invalid_target", error_description = "resource must be an absolute URI" });
    }

    return null;
}

bool IsAcceptableRedirectUri(string? uri)
{
    if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed) || !string.IsNullOrEmpty(parsed.Fragment))
    {
        return false;
    }

    return parsed.Scheme == Uri.UriSchemeHttps || (parsed.Scheme == Uri.UriSchemeHttp && parsed.IsLoopback);
}

string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;

// Structural Token Builder
string GenerateJwtToken(RSA rsa, string issuer, string audience, string email, string name, string[] roles, Dictionary<string, object>? extraClaims = null)
{
    var header = new { alg = "RS256", typ = "JWT", kid };
    var payload = new Dictionary<string, object>
    {
        ["iss"] = issuer,
        ["jti"] = Guid.NewGuid().ToString("N"), // unique per token, so two tokens issued in the same second still differ
        ["sub"] = email,
        ["aud"] = audience,
        ["exp"] = DateTimeOffset.UtcNow.AddSeconds(accessTokenSeconds).ToUnixTimeSeconds(),
        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        ["name"] = name,
        ["roles"] = roles // Injected roles exactly like Azure Entra ID
    };
    foreach (var claim in extraClaims ?? new Dictionary<string, object>())
    {
        payload[claim.Key] = claim.Value;
    }

    string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
    string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

    string stringToSign = $"{encodedHeader}.{encodedPayload}";
    byte[] signatureBytes = rsa.SignData(Encoding.UTF8.GetBytes(stringToSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    return $"{stringToSign}.{Base64UrlEncode(signatureBytes)}";
}

string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).Replace("=", "").Replace("+", "-").Replace("/", "_");

app.Run();

// Data container for active login loops
record AuthFlowSession(string ClientId, string RedirectUri, string CodeChallenge, string UserEmail, string UserName, string[] UserRoles, string? Resource, string? Scope);

// A refresh token as the IdP remembers it. Used flips to true the one time it is exchanged.
class RefreshRecord(AuthFlowSession session, string familyId, DateTimeOffset expiresAt)
{
    public AuthFlowSession Session { get; } = session;
    public string FamilyId { get; } = familyId;
    public DateTimeOffset ExpiresAt { get; } = expiresAt;
    public bool Used { get; set; }
}
