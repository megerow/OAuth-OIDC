using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// 1. Create a global RSA Key Pair to sign all tokens issued by this server session
using RSA rsaKey = RSA.Create(2048);

// 2. Mock Database: Simulates a session created during Step 3 of the flow.
// Maps a temporary auth code -> to the client's registered PKCE Code Challenge.
var mockSessionDatabase = new Dictionary<string, string>
{
    // Key: The temporary code issued from the browser
    // Value: The SHA-256 Base64Url challenge the client gave us during /authorize
    { "mock_auth_code_12345", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }
};

// 3. Define the /token Endpoint (Handles Steps 5, 6, and 7 of the flow)
app.MapPost("/token", async (HttpContext context) =>
{
    // Extract form data from the incoming POST request
    var form = await context.Request.ReadFormAsync();
    string? code = form["code"];
    string? codeVerifier = form["code_verifier"];
    string? clientId = form["client_id"];

    // Basic Request Validation
    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(codeVerifier))
    {
        return Results.BadRequest(new { error = "invalid_request", description = "Missing code or code_verifier" });
    }

    // Lookup the code in our mock database
    if (!mockSessionDatabase.TryGetValue(code, out var storedChallenge))
    {
        return Results.BadRequest(new { error = "invalid_grant", description = "Authorization code not found or expired" });
    }

    // === STEP 6: PKCE VERIFICATION ===
    // Hash the incoming plaintext code_verifier using SHA-256
    using var sha256 = SHA256.Create();
    byte[] verifierBytes = Encoding.UTF8.GetBytes(codeVerifier);
    byte[] computedHashBytes = sha256.ComputeHash(verifierBytes);
    string computedChallenge = Base64UrlEncode(computedHashBytes);

    // Securely compare the calculated challenge against the stored challenge
    if (computedChallenge != storedChallenge)
    {
        return Results.BadRequest(new { error = "invalid_grant", description = "PKCE verification failed. Code verifier mismatch." });
    }

    // Clean up the code so it can never be used a second time (OIDC security mandate)
    mockSessionDatabase.Remove(code);

    // === STEP 7: TOKEN DELIVERY ===
    // Generate the OIDC tokens using our RSA private key from Milestone 1
    string idToken = GenerateJwtToken(rsaKey, clientId ?? "unknown_client");

    return Results.Ok(new
    {
        access_token = "mock_access_token_abcde12345",
        token_type = "Bearer",
        expires_in = 3600,
        id_token = idToken
    });
});

// Helper: Generates a cryptographically signed OIDC Identity Token
string GenerateJwtToken(RSA rsa, string clientId)
{
    var header = new { alg = "RS256", typ = "JWT" };
    var payload = new
    {
        iss = "https://localhost:5001", 
        sub = "user_987654321", // Hardcoded mock user profile
        aud = clientId, 
        exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
        iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        name = "Jane Doe"
    };

    string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
    string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
    
    string stringToSign = $"{encodedHeader}.{encodedPayload}";
    byte[] signatureBytes = rsa.SignData(Encoding.UTF8.GetBytes(stringToSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    
    return $"{stringToSign}.{Base64UrlEncode(signatureBytes)}";
}

// Helper: Standard Base64Url encoder used by OAuth standards
string Base64UrlEncode(byte[] input)
{
    return Convert.ToBase64String(input).Replace("=", "").Replace("+", "-").Replace("/", "_");
}

app.Run();
