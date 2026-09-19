using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

// 1. Core Configuration
const string IdentityProviderBaseUrl = "http://localhost:5121";
const string ProtectedApiBaseUrl = "http://localhost:5062";
const string ClientId ="my_learning_client_app";
const string RedirectUri = "http://localhost:8080/callback/"; // Our local capture hook

// 2. Generate PKCE values cryptographically
// Create a random 43-character string (Code Verifier)
string codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
    .Replace("=", "").Replace("+", "-").Replace("/", "_").Substring(0, 43);

// Compute the SHA-256 Hash of that verifier (Code Challenge)
using var sha256 = SHA256.Create();
byte[] challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
string codeChallenge = Convert.ToBase64String(challengeBytes)
    .Replace("=", "").Replace("+", "-").Replace("/", "_");

// 3. Set up a quick HTTP Listener to wait for the authorization code redirect
using var listener = new HttpListener();
listener.Prefixes.Add(RedirectUri);
listener.Start();

// 4. Construct the complex Authorization URL and trigger the default system browser
string authUrl = $"{IdentityProviderBaseUrl}/authorize?" +
                 $"client_id={Uri.EscapeDataString(ClientId)}&" +
                 $"redirect_uri={Uri.EscapeDataString(RedirectUri)}&" +
                 $"code_challenge={Uri.EscapeDataString(codeChallenge)}&" +
                 "code_challenge_method=S256";

Console.WriteLine("=================================================");
Console.WriteLine("Launching system browser to initiate OAuth login...");
Console.WriteLine("=================================================");

// Open user's default browser (Works safely across Windows, Mac, and Linux)
Process.Start(new ProcessStartInfo { FileName = authUrl, UseShellExecute = true });

// 5. Block execution until the browser redirects back to http://localhost:8080/callback/
HttpListenerContext context = await listener.GetContextAsync();
HttpListenerRequest request = context.Request;

// Extract the one-time code returned by your identity service in the query string
string? authorizationCode = request.QueryString["code"];

// Render a friendly "Success" response to the user's browser window
byte[] responseBytes = Encoding.UTF8.GetBytes("<html><body><h2>Login successful! You can return to your application console.</h2></body></html>");
context.Response.ContentType = "text/html";
context.Response.ContentLength64 = responseBytes.Length;
await context.Response.OutputStream.WriteAsync(responseBytes, 0, responseBytes.Length);
context.Response.OutputStream.Close();
listener.Stop();

if (string.IsNullOrEmpty(authorizationCode))
{
    Console.WriteLine("Failed to capture authorization code from browser redirect.");
    return;
}

Console.WriteLine($"\n[Captured Code]: {authorizationCode}");
Console.WriteLine("Exchanging the code for OIDC identity tokens via background channel...");

// 6. Execute the Back-Channel POST Request to the /token endpoint
// Notice we pass the raw, unhashed codeVerifier here.
using var httpClient = new HttpClient();
var tokenRequestContent = new FormUrlEncodedContent(new Dictionary<string, string>
{
    { "grant_type", "authorization_code" },
    { "client_id", ClientId },
    { "redirect_uri", RedirectUri },
    { "code", authorizationCode },
    { "code_verifier", codeVerifier }
});

HttpResponseMessage tokenResponse = await httpClient.PostAsync($"{IdentityProviderBaseUrl}/token", tokenRequestContent);
string jsonResponseBody = await tokenResponse.Content.ReadAsStringAsync();

Console.WriteLine("\n=================== RESPONSE FROM SERVER ===================");
Console.WriteLine(jsonResponseBody);
Console.WriteLine("============================================================");

if (!tokenResponse.IsSuccessStatusCode)
{
    return;
}

// 7. Call the protected API. The service's access_token is opaque, so the id_token (a JWT) is the bearer token.
using var tokenJson = System.Text.Json.JsonDocument.Parse(jsonResponseBody);
string idToken = tokenJson.RootElement.GetProperty("id_token").GetString()!;

foreach (string path in new[] { "/api/public", "/api/admin-dashboard", "/api/billing" })
{
    var apiRequest = new HttpRequestMessage(HttpMethod.Get, $"{ProtectedApiBaseUrl}{path}");
    apiRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", idToken);

    try
    {
        HttpResponseMessage apiResponse = await httpClient.SendAsync(apiRequest);
        Console.WriteLine($"\nGET {path} -> {(int)apiResponse.StatusCode} {apiResponse.StatusCode}");
        Console.WriteLine(await apiResponse.Content.ReadAsStringAsync());
    }
    catch (HttpRequestException ex)
    {
        Console.WriteLine($"\nGET {path} -> could not reach {ProtectedApiBaseUrl} ({ex.Message}). Is MiniProtectedApi running?");
        break;
    }
}
