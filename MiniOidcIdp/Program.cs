using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.AspNetCore.WebUtilities;

var builder = WebApplication.CreateBuilder(args);

// 0. Configuration: how users sign in, which groups map to which roles, who may edit the mappings, and where state is kept
var idp = builder.Configuration.GetSection("Idp").Get<IdpOptions>() ?? new IdpOptions();
bool windowsMode = idp.AuthenticationMode != IdpMode.Persona;

if (windowsMode && !OperatingSystem.IsWindows())
{
    throw new InvalidOperationException($"Idp:AuthenticationMode '{idp.AuthenticationMode}' needs Windows. Use 'Persona' on this machine.");
}

string windowsScheme = idp.AuthenticationMode == IdpMode.WindowsIis ? IISDefaults.AuthenticationScheme : NegotiateDefaults.AuthenticationScheme;
if (idp.AuthenticationMode == IdpMode.WindowsKestrel)
{
    builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
}
else if (idp.AuthenticationMode == IdpMode.WindowsIis)
{
    builder.Services.AddAuthentication(IISDefaults.AuthenticationScheme);
}

// Stores for clients, codes, refresh tokens, role mappings and signing keys: in memory by default, or a database
var persistence = builder.Services.AddIdpPersistence(builder.Configuration, idp);
builder.Services.AddAntiforgery();

var app = builder.Build();

// Creates the schema, seeds the role mappings and makes sure a signing key exists. Stops the IdP if anything is wrong.
await app.Services.InitializeIdpPersistenceAsync(idp);

if (windowsMode)
{
    app.UseAuthentication();
}

var clients = app.Services.GetRequiredService<IClientStore>();
var codeStore = app.Services.GetRequiredService<IAuthorizationCodeStore>();
var refreshStore = app.Services.GetRequiredService<IRefreshTokenStore>();
var roleMappings = app.Services.GetRequiredService<IRoleMappingStore>();
var keys = app.Services.GetRequiredService<ISigningKeyProvider>();

app.Logger.LogInformation("Authentication mode: {Mode}. State kept in: {Provider}", idp.AuthenticationMode, persistence.Provider == PersistenceProvider.None ? "memory" : persistence.Provider.ToString());

int accessTokenSeconds = Math.Max(1, app.Configuration.GetValue<int>("Tokens:AccessTokenSeconds", 3600));
int refreshTokenSeconds = Math.Max(1, app.Configuration.GetValue<int>("Tokens:RefreshTokenSeconds", 86400));
int refreshTokenMaxSeconds = Math.Max(1, app.Configuration.GetValue<int>("Tokens:RefreshTokenMaxSeconds", 604800));
int authorizationCodeSeconds = Math.Max(1, app.Configuration.GetValue<int>("Tokens:AuthorizationCodeSeconds", 300));

const int MaxDynamicClients = 1000;
const int MaxRedirectUris = 10;
const int MaxUriLength = 2048;
const int MaxClientNameLength = 200;

string IssuerFor(HttpRequest r) =>
    !string.IsNullOrWhiteSpace(idp.Issuer) ? idp.Issuer.TrimEnd('/') : $"{r.Scheme}://{r.Host}";
string Html(string? s) => WebUtility.HtmlEncode(s ?? "");

var indented = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true };

// Windows sign-in: the server (IIS) or the Negotiate handler (Kestrel) does the NTLM/Kerberos handshake for us
async Task<IdpUser?> AuthenticateWindowsAsync(HttpContext ctx)
{
    var result = await ctx.AuthenticateAsync(windowsScheme);
    if (result.Succeeded && OperatingSystem.IsWindows() && result.Principal?.Identity is WindowsIdentity identity)
    {
        return IdpUsers.FromWindows(identity);
    }

    return null;
}

IResult ChallengeWindows() => Results.Challenge(authenticationSchemes: new[] { windowsScheme });

// Authorization server metadata, served both as OIDC discovery and as RFC 8414 metadata (MCP clients look for either)
object ServerMetadata(string issuer)
{
    var metadata = new Dictionary<string, object>
    {
        ["issuer"] = issuer,
        ["authorization_endpoint"] = $"{issuer}/authorize",
        ["token_endpoint"] = $"{issuer}/token",
        ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
        ["revocation_endpoint"] = $"{issuer}/revoke",
        ["revocation_endpoint_auth_methods_supported"] = new[] { "none" },
        ["end_session_endpoint"] = $"{issuer}/logout",
        ["response_types_supported"] = new[] { "code" },
        ["grant_types_supported"] = new[] { "authorization_code", "refresh_token" },
        ["subject_types_supported"] = new[] { "public" },
        ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
        ["code_challenge_methods_supported"] = new[] { "S256" },
        ["token_endpoint_auth_methods_supported"] = new[] { "none" },
        ["scopes_supported"] = new[] { "openid", "offline_access", "mcp:tools" }
    };

    if (idp.AllowDynamicClientRegistration)
    {
        metadata["registration_endpoint"] = $"{issuer}/register";
    }

    return metadata;
}

app.MapGet("/.well-known/openid-configuration", (HttpRequest request) => Results.Json(ServerMetadata(IssuerFor(request))));
app.MapGet("/.well-known/oauth-authorization-server", (HttpRequest request) => Results.Json(ServerMetadata(IssuerFor(request))));

// Public signing keys (JWK) used to verify the RS256 signature on issued tokens. During a rotation this lists more than one.
app.MapGet("/.well-known/jwks.json", async () =>
{
    var published = await keys.GetPublishedAsync();
    return Results.Json(new
    {
        keys = published.Select(k => new { kty = "RSA", use = "sig", alg = "RS256", kid = k.Kid, n = k.Modulus, e = k.Exponent })
    });
});

// Dynamic Client Registration (RFC 7591): public clients register their redirect URIs and receive a client_id
app.MapPost("/register", async (HttpContext context) =>
{
    if (!idp.AllowDynamicClientRegistration)
    {
        return Results.NotFound();
    }

    // The endpoint is open to anyone, so keep what it accepts small
    var bodyLimit = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (bodyLimit is { IsReadOnly: false })
    {
        bodyLimit.MaxRequestBodySize = 32 * 1024;
    }

    JsonDocument document;
    try
    {
        document = await JsonDocument.ParseAsync(context.Request.Body);
    }
    catch (JsonException)
    {
        return Results.Json(new { error = "invalid_client_metadata", error_description = "Body must be JSON" }, statusCode: 400);
    }

    using (document)
    {
        var body = document.RootElement;
        if (body.ValueKind != JsonValueKind.Object)
        {
            return Results.Json(new { error = "invalid_client_metadata", error_description = "Body must be a JSON object" }, statusCode: 400);
        }

        string? clientName = body.TryGetProperty("client_name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String ? nameElement.GetString() : null;
        if (clientName is { Length: > MaxClientNameLength })
        {
            return Results.Json(new { error = "invalid_client_metadata", error_description = $"client_name is limited to {MaxClientNameLength} characters" }, statusCode: 400);
        }

        var redirectUris = ReadUriList(body, "redirect_uris", out var redirectError);
        if (redirectUris == null || redirectUris.Count == 0)
        {
            return Results.Json(new { error = "invalid_redirect_uri", error_description = redirectError ?? "redirect_uris is required" }, statusCode: 400);
        }

        var postLogoutUris = ReadUriList(body, "post_logout_redirect_uris", out var postLogoutError) ?? [];
        if (postLogoutError != null)
        {
            return Results.Json(new { error = "invalid_client_metadata", error_description = postLogoutError }, statusCode: 400);
        }

        string clientId = "client_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        if (!await clients.TryRegisterAsync(new ClientInfo(clientId, redirectUris, postLogoutUris), clientName, MaxDynamicClients))
        {
            return Results.Json(new { error = "invalid_client_metadata", error_description = "The limit on registered clients has been reached" }, statusCode: 400);
        }

        return Results.Json(new
        {
            client_id = clientId,
            client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            client_name = clientName,
            redirect_uris = redirectUris,
            post_logout_redirect_uris = postLogoutUris,
            token_endpoint_auth_method = "none",
            grant_types = new[] { "authorization_code", "refresh_token" },
            response_types = new[] { "code" }
        }, statusCode: 201);
    }
});

// Reads an optional array of redirect-style URIs. Returns null with an error message when a value is not acceptable.
List<string>? ReadUriList(JsonElement body, string name, out string? error)
{
    error = null;
    var list = new List<string>();
    if (!body.TryGetProperty(name, out var element))
    {
        return list;
    }

    if (element.ValueKind != JsonValueKind.Array || element.GetArrayLength() > MaxRedirectUris)
    {
        error = $"{name} must be an array of at most {MaxRedirectUris} URIs";
        return null;
    }

    foreach (var item in element.EnumerateArray())
    {
        string? uri = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
        if (uri is not { Length: <= MaxUriLength } || !IsAcceptableRedirectUri(uri))
        {
            error = $"{name} must hold absolute https URIs or http loopback URIs, without fragments, of at most {MaxUriLength} characters";
            return null;
        }

        if (!list.Contains(uri))
        {
            list.Add(uri);
        }
    }

    return list;
}

// 2. Endpoint: The Initial OIDC Redirection Trigger (Step 1 & 2 of the Flow)
app.MapGet("/authorize", async (HttpContext context, [FromQuery] string client_id, [FromQuery] string redirect_uri, [FromQuery] string code_challenge, [FromQuery] string code_challenge_method,
    [FromQuery] string? resource, [FromQuery] string? scope, [FromQuery] string? state) =>
{
    var error = await ValidateAuthorizationRequestAsync(client_id, redirect_uri, code_challenge_method, resource);
    if (error != null)
    {
        return error;
    }

    // Windows modes: no login form. The browser answers the Windows challenge and the code is issued straight away.
    if (windowsMode)
    {
        var user = await AuthenticateWindowsAsync(context);
        if (user == null)
        {
            return ChallengeWindows();
        }

        return await IssueCodeAsync(user, client_id, redirect_uri, code_challenge, NullIfEmpty(resource), NullIfEmpty(scope), NullIfEmpty(state));
    }

    // Persona mode: the login form, prefilled with the first persona so a first-time visitor can just click the button
    return LoginForm(client_id, redirect_uri, code_challenge, code_challenge_method, resource, scope, state,
        idp.Personas.FirstOrDefault()?.Email ?? "", idp.Personas.FirstOrDefault()?.Password ?? "", null);
});

// A lightweight, raw HTML login form. It is also shown again, with an error, when a sign-in fails.
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

// 3. Endpoint: Form Post-Back Process (Step 3 & 4 of the Flow), Persona mode only
app.MapPost("/login", async (HttpContext context) =>
{
    if (windowsMode)
    {
        return Results.NotFound();
    }

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
    var error = await ValidateAuthorizationRequestAsync(clientId, redirectUri, form["code_challenge_method"].ToString(), resource);
    if (error != null || string.IsNullOrEmpty(codeChallenge))
    {
        return error ?? Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge is required" });
    }

    // Validate Credentials. A wrong password shows the form again with a generic message (no hint about which part was wrong)
    // and keeps the request details, so the user can retry. The password is never echoed back.
    var persona = idp.Personas.FirstOrDefault(p => string.Equals(p.Email, email, StringComparison.OrdinalIgnoreCase));
    if (persona == null || persona.Password != password)
    {
        return LoginForm(clientId, redirectUri, codeChallenge, form["code_challenge_method"].ToString(), resource, scope, state, email, "", "Incorrect email or password.");
    }

    return await IssueCodeAsync(IdpUsers.FromPersona(persona), clientId, redirectUri, codeChallenge, resource, scope, state);
});

// Creates the one-time authorization code for a signed-in user and redirects back to the client
async Task<IResult> IssueCodeAsync(IdpUser user, string clientId, string redirectUri, string codeChallenge, string? resource, string? scope, string? state)
{
    // Groups become application roles here, at sign-in, using the current mapping table
    string[] roles = IdpUsers.ResolveRoles(user, await roleMappings.SnapshotAsync());

    // Generate a secure, randomized one-time authorization code
    string authorizationCode = "auth_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    // Keep what it stands for until the client trades it in at /token, or it expires
    await codeStore.SaveAsync(authorizationCode, new AuthFlowSession(clientId, redirectUri, codeChallenge, user.Subject, user.Account, user.Name, roles, resource, scope),
        DateTimeOffset.UtcNow.AddSeconds(authorizationCodeSeconds));

    // Redirect the browser window straight back to the client application with the code (and the client's state, if any)
    var callbackParams = new Dictionary<string, string?> { ["code"] = authorizationCode };
    if (state != null)
    {
        callbackParams["state"] = state;
    }
    return Results.Redirect(QueryHelpers.AddQueryString(redirectUri, callbackParams));
}

// 4. Endpoint: /token. Two grants: authorization_code (Steps 5-7 of the flow) and refresh_token.
app.MapPost("/token", async (HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";

    var form = await context.Request.ReadFormAsync();
    return form["grant_type"].ToString() switch
    {
        "" or "authorization_code" => await ExchangeAuthorizationCodeAsync(context, form),
        "refresh_token" => await ExchangeRefreshTokenAsync(context, form),
        _ => TokenError("unsupported_grant_type", "Supported grants: authorization_code, refresh_token")
    };
});

IResult TokenError(string error, string description) =>
    Results.Json(new { error, error_description = description }, statusCode: StatusCodes.Status400BadRequest);

string[] SplitScopes(string? scope) =>
    string.IsNullOrWhiteSpace(scope) ? [] : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

async Task<IResult> ExchangeAuthorizationCodeAsync(HttpContext context, IFormCollection form)
{
    string? code = form["code"];
    string? codeVerifier = form["code_verifier"];

    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(codeVerifier))
    {
        return TokenError("invalid_request", "code and code_verifier are required");
    }

    var session = await codeStore.FindAsync(code);
    if (session == null)
    {
        return TokenError("invalid_grant", "Code not found or expired");
    }

    // PKCE Verification
    string computedChallenge = Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier)));
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

    // Burn the code so it is strictly single-use. If another request got there first, this one loses.
    if (!await codeStore.ConsumeAsync(code))
    {
        return TokenError("invalid_grant", "Code not found or expired");
    }

    // Every refresh token issued from this login shares a family id, so a replayed one can revoke them all. The same id is the token's sid claim.
    return await IssueTokensAsync(context, session, Base64Url.Encode(RandomNumberGenerator.GetBytes(12)), DateTimeOffset.UtcNow, null, tokenResource);
}

// Refresh grant (RFC 6749 section 6). Each refresh token works once: using it returns a new one in the same family.
// Presenting one that was already used means it leaked, so the whole family is revoked (the OAuth security BCP's advice, and what Okta does).
async Task<IResult> ExchangeRefreshTokenAsync(HttpContext context, IFormCollection form)
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

    var record = await refreshStore.FindAsync(presented);
    if (record == null || record.ExpiresAt <= DateTimeOffset.UtcNow || record.Session.ClientId != clientId)
    {
        return invalid;
    }

    if (record.Used)
    {
        await refreshStore.RevokeFamilyAsync(record.FamilyId);
        app.Logger.LogWarning("Refresh token reuse detected for {Account}: revoked all refresh tokens from that sign-in", record.Session.Account);
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

    // Only one request can flip the token to used. Losing that race looks exactly like a replay, so it is treated as one.
    if (!await refreshStore.TryMarkUsedAsync(presented))
    {
        await refreshStore.RevokeFamilyAsync(record.FamilyId);
        app.Logger.LogWarning("Refresh token used twice at once for {Account}: revoked all refresh tokens from that sign-in", record.Session.Account);
        return invalid;
    }

    var current = await ReevaluateSessionAsync(record.Session);
    if (current == null)
    {
        await refreshStore.RevokeFamilyAsync(record.FamilyId);
        return invalid;
    }

    return await IssueTokensAsync(context, current, record.FamilyId, record.FamilyCreatedAt, requestedScope, tokenResource);
}

// Persona mode re-reads the user and the current role mappings at every refresh, so a role edit or a removed user takes effect without a new sign-in.
// Windows modes cannot re-read group membership without the user's browser sign-in, so the roles from sign-in are kept until they sign in again.
async Task<AuthFlowSession?> ReevaluateSessionAsync(AuthFlowSession session)
{
    if (windowsMode)
    {
        return session;
    }

    var persona = idp.Personas.FirstOrDefault(p => p.Sid == session.Subject);
    if (persona == null)
    {
        return null;
    }

    return session with
    {
        Account = persona.Email,
        Name = persona.Name,
        Roles = IdpUsers.ResolveRoles(IdpUsers.FromPersona(persona), await roleMappings.SnapshotAsync())
    };
}

// Builds the token response for either grant
async Task<IResult> IssueTokensAsync(HttpContext context, AuthFlowSession session, string familyId, DateTimeOffset familyCreatedAt, string? narrowedScope, string? tokenResource)
{
    string issuer = IssuerFor(context.Request);
    var signingKey = await keys.GetActiveAsync();

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
    string accessToken = GenerateJwtToken(signingKey, issuer, audience, session, familyId, accessTokenClaims);

    // The id_token is for the client itself, so its audience is always the client_id
    string idToken = GenerateJwtToken(signingKey, issuer, session.ClientId, session, familyId);

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
        // An opaque random string: the client cannot read it, and only this IdP knows what it stands for.
        // Its lifetime slides (every refresh hands out a new one), but never past the cap counted from the original sign-in.
        string refreshToken = "rt_" + Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;
        var expiresAt = Earlier(now.AddSeconds(refreshTokenSeconds), familyCreatedAt.AddSeconds(refreshTokenMaxSeconds));
        await refreshStore.SaveAsync(refreshToken, session, familyId, familyCreatedAt, expiresAt);
        response["refresh_token"] = refreshToken;
    }

    return Results.Json(response);
}

DateTimeOffset Earlier(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;

// Token revocation (RFC 7009). A public client hands back a refresh token it no longer wants, or suspects has leaked,
// and every refresh token from that sign-in stops working. Access tokens are self-contained and simply expire.
app.MapPost("/revoke", async (HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";

    var form = await context.Request.ReadFormAsync();
    string token = form["token"].ToString();
    string? clientId = NullIfEmpty(form["client_id"].ToString());
    string hint = form["token_type_hint"].ToString();

    if (clientId == null || await clients.FindAsync(clientId) == null)
    {
        return Results.Json(new { error = "invalid_client", error_description = "Unknown client_id" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (token == "")
    {
        return TokenError("invalid_request", "token is required");
    }

    if (hint == "access_token" || token.Count(c => c == '.') == 2)
    {
        return TokenError("unsupported_token_type", "Only refresh tokens can be revoked. An access token stops working when it expires.");
    }

    // Unknown, expired, already revoked, or issued to another client: all answered the same way, so nothing is revealed
    var record = await refreshStore.FindAsync(token);
    if (record != null && record.Session.ClientId == clientId)
    {
        await refreshStore.RevokeFamilyAsync(record.FamilyId);
        app.Logger.LogInformation("Refresh token revoked by client {Client} for {Account}", clientId, record.Session.Account);
    }

    return Results.Ok();
});

// Logout (OpenID Connect RP-Initiated Logout). The client sends the id_token it received. Its sid claim names the sign-in to end.
app.MapMethods("/logout", new[] { "GET", "POST" }, async (HttpContext context) =>
{
    var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : null;
    string? Param(string name)
    {
        string value = context.Request.Query[name].ToString();
        if (value == "" && form != null)
        {
            value = form[name].ToString();
        }
        return NullIfEmpty(value);
    }

    string? hint = Param("id_token_hint");
    string? requestedClient = Param("client_id");
    string? postLogoutUri = Param("post_logout_redirect_uri");
    string? state = Param("state");

    // Without a valid hint nobody can be identified, so nothing is ended and nobody is redirected
    var hinted = hint == null ? null : await ValidateIdTokenHintAsync(context.Request, hint);
    if (hinted == null || (requestedClient != null && requestedClient != hinted.ClientId))
    {
        return SignedOutPage();
    }

    await refreshStore.RevokeFamilyAsync(hinted.Sid);
    app.Logger.LogInformation("Logout: ended sign-in {Sid} for client {Client}", hinted.Sid, hinted.ClientId);

    // Only a redirect address registered for this client is honoured, or the endpoint could be used to bounce people to any site
    var client = await clients.FindAsync(hinted.ClientId);
    if (postLogoutUri != null && client != null && client.PostLogoutRedirectUris.Contains(postLogoutUri))
    {
        return Results.Redirect(state == null ? postLogoutUri : QueryHelpers.AddQueryString(postLogoutUri, "state", state));
    }

    return SignedOutPage();
});

IResult SignedOutPage() => Results.Content($@"
    <html>
    <body style='font-family: sans-serif; max-width: 480px; margin: 50px auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px;'>
        <h2>Signed out</h2>
        <p>You have signed out of the identity provider.</p>
        {(windowsMode ? "<p>This IdP signs you in with your Windows account, so opening an application again may sign you straight back in.</p>" : "")}
    </body>
    </html>", "text/html");

// Checks an id_token the IdP issued: its signature (against its own keys), issuer and audience. Expiry is deliberately ignored,
// because a client logging out is often holding an id_token that has already expired.
async Task<LogoutHint?> ValidateIdTokenHintAsync(HttpRequest request, string token)
{
    var parts = token.Split('.');
    if (parts.Length != 3)
    {
        return null;
    }

    try
    {
        using var header = JsonDocument.Parse(Base64Url.Decode(parts[0]));
        if (header.RootElement.GetProperty("alg").GetString() != "RS256")
        {
            return null;
        }

        string? kid = header.RootElement.TryGetProperty("kid", out var kidElement) ? kidElement.GetString() : null;
        var rsa = kid == null ? null : await keys.GetVerificationKeyAsync(kid);
        if (rsa == null || !rsa.VerifyData(Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}"), Base64Url.Decode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return null;
        }

        using var payload = JsonDocument.Parse(Base64Url.Decode(parts[1]));
        var root = payload.RootElement;

        // An access token also has an sid, but it is not meant for this, so only id_tokens (which have no client_id claim) are accepted
        if (root.TryGetProperty("client_id", out _) || root.GetProperty("iss").GetString() != IssuerFor(request))
        {
            return null;
        }

        string? audience = root.GetProperty("aud").ValueKind == JsonValueKind.String ? root.GetProperty("aud").GetString() : null;
        string? sid = root.TryGetProperty("sid", out var sidElement) ? sidElement.GetString() : null;
        if (audience == null || sid == null || await clients.FindAsync(audience) == null)
        {
            return null;
        }

        return new LogoutHint(audience, sid);
    }
    catch (Exception ex) when (ex is FormatException or JsonException or KeyNotFoundException or InvalidOperationException or CryptographicException)
    {
        return null;
    }
}

// 5. Admin page: shows the roles the IdP returns for users, lets an administrator edit the group-to-role mappings,
// and end a user's sign-ins
async Task<(IdpUser? User, IResult? Stop)> AdminSignInAsync(HttpContext ctx)
{
    if (!idp.EnableAdminUi)
    {
        return (null, Results.NotFound());
    }

    if (!windowsMode)
    {
        return (null, null);
    }

    var user = await AuthenticateWindowsAsync(ctx);
    return user == null ? (null, ChallengeWindows()) : (user, null);
}

// Persona mode is a development convenience, so anyone using it may edit. Windows mode needs membership in AdminGroup.
bool CanEdit(IdpUser? windowsUser) =>
    !windowsMode || (windowsUser != null && !string.IsNullOrWhiteSpace(idp.AdminGroup) && windowsUser.IsInGroup(idp.AdminGroup));

async Task<List<UserReport>> BuildReportsAsync(IdpUser? windowsUser)
{
    var mappings = await roleMappings.SnapshotAsync();
    var users = windowsMode ? new List<IdpUser> { windowsUser! } : idp.Personas.Select(IdpUsers.FromPersona).ToList();
    return users.Select(u => IdpUsers.Report(u, mappings)).ToList();
}

// Other people's sign-ins are only shown to someone who could end them
async Task<IReadOnlyList<ActiveSession>?> SessionsForAsync(IdpUser? windowsUser) =>
    CanEdit(windowsUser) ? await refreshStore.ListActiveSessionsAsync() : null;

app.MapGet("/admin/roles", async (HttpContext ctx, IAntiforgery antiforgery, string? notice) =>
{
    var (user, stop) = await AdminSignInAsync(ctx);
    if (stop != null)
    {
        return stop;
    }

    var html = AdminPage.Render(idp.AuthenticationMode, await BuildReportsAsync(user), await roleMappings.SnapshotAsync(), await SessionsForAsync(user),
        CanEdit(user), idp.AdminGroup, antiforgery.GetAndStoreTokens(ctx), notice);
    return Results.Content(html, "text/html");
});

app.MapGet("/admin/roles.json", async (HttpContext ctx) =>
{
    var (user, stop) = await AdminSignInAsync(ctx);
    if (stop != null)
    {
        return stop;
    }

    return Results.Json(new
    {
        mode = idp.AuthenticationMode.ToString(),
        canEdit = CanEdit(user),
        users = await BuildReportsAsync(user),
        roleMappings = await roleMappings.SnapshotAsync(),
        sessions = await SessionsForAsync(user)
    }, indented);
});

// Every admin change goes through here: it must come from an admin, and from our own page (a browser sends Windows credentials by itself)
async Task<IResult> AdminPostAsync(HttpContext ctx, IAntiforgery antiforgery, Func<IFormCollection, IdpUser?, Task<string>> action)
{
    var (user, stop) = await AdminSignInAsync(ctx);
    if (stop != null)
    {
        return stop;
    }

    if (!CanEdit(user))
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    try
    {
        await antiforgery.ValidateRequestAsync(ctx);
    }
    catch (AntiforgeryValidationException)
    {
        return Results.BadRequest(new { error = "invalid_request", error_description = "Missing or invalid anti-forgery token" });
    }

    var form = await ctx.Request.ReadFormAsync();
    string notice = await action(form, user);
    return Results.Redirect("/admin/roles?notice=" + Uri.EscapeDataString(notice));
}

async Task<string> EditMappingAsync(IFormCollection form, IdpUser? user, bool add)
{
    var mapping = new RoleMapping { Group = form["group"].ToString().Trim(), Role = form["role"].ToString().Trim() };
    string? error = add ? await roleMappings.AddAsync(mapping) : await roleMappings.RemoveAsync(mapping);

    if (error == null)
    {
        app.Logger.LogInformation("Role mapping {Action} by {Editor}: {Group} -> {Role}", add ? "added" : "removed", user?.Account ?? "persona-mode", mapping.Group, mapping.Role);
    }

    return error ?? (add ? "Mapping added." : "Mapping removed.");
}

async Task<string> RevokeSessionsAsync(IFormCollection form, IdpUser? user)
{
    string subject = form["subject"].ToString();
    if (subject == "")
    {
        return "Choose a user.";
    }

    int ended = await refreshStore.RevokeBySubjectAsync(subject);
    app.Logger.LogInformation("Sessions revoked by {Editor} for {Subject}: {Count} sign-in(s)", user?.Account ?? "persona-mode", subject, ended);
    return $"Ended {ended} sign-in(s). Access tokens already issued keep working for up to {accessTokenSeconds} seconds.";
}

app.MapPost("/admin/roles/mappings", (HttpContext ctx, IAntiforgery antiforgery) =>
    AdminPostAsync(ctx, antiforgery, (form, user) => EditMappingAsync(form, user, add: true)));
app.MapPost("/admin/roles/mappings/delete", (HttpContext ctx, IAntiforgery antiforgery) =>
    AdminPostAsync(ctx, antiforgery, (form, user) => EditMappingAsync(form, user, add: false)));
app.MapPost("/admin/roles/sessions/revoke", (HttpContext ctx, IAntiforgery antiforgery) =>
    AdminPostAsync(ctx, antiforgery, RevokeSessionsAsync));

async Task<IResult?> ValidateAuthorizationRequestAsync(string clientId, string redirectUri, string codeChallengeMethod, string? resource)
{
    // Unknown client or unregistered redirect: never redirect back, since that would be an open redirect
    var client = await clients.FindAsync(clientId);
    if (client == null || !client.RedirectUris.Contains(redirectUri))
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

// Structural Token Builder. sid ties the token to the sign-in it came from, so a logout can end that sign-in.
string GenerateJwtToken(SigningKey key, string issuer, string audience, AuthFlowSession user, string sid, Dictionary<string, object>? extraClaims = null)
{
    var header = new { alg = "RS256", typ = "JWT", kid = key.Kid };
    var payload = new Dictionary<string, object>
    {
        ["iss"] = issuer,
        ["jti"] = Guid.NewGuid().ToString("N"), // unique per token, so two tokens issued in the same second still differ
        ["sub"] = user.Subject,
        ["sid"] = sid,
        ["aud"] = audience,
        ["exp"] = DateTimeOffset.UtcNow.AddSeconds(accessTokenSeconds).ToUnixTimeSeconds(),
        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        ["name"] = user.Name,
        ["preferred_username"] = user.Account,
        ["roles"] = user.Roles // Injected roles exactly like Azure Entra ID
    };
    foreach (var claim in extraClaims ?? new Dictionary<string, object>())
    {
        payload[claim.Key] = claim.Value;
    }

    string encodedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
    string encodedPayload = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

    string stringToSign = $"{encodedHeader}.{encodedPayload}";
    byte[] signatureBytes = key.Rsa.SignData(Encoding.UTF8.GetBytes(stringToSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    return $"{stringToSign}.{Base64Url.Encode(signatureBytes)}";
}

app.Run();

// The client and sign-in a logout request's id_token_hint points at
record LogoutHint(string ClientId, string Sid);
