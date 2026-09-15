using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class Program
{
    static void Main()
    {
        // 1. Generate an RSA Key Pair (Private for signing, Public for verification)
        using RSA rsa = RSA.Create(2048);

        // 2. Define the OIDC Claims (The Payload)
        // These are the exact standard keys Azure and Okta use.
        var payloadObj = new
        {
            iss = "https://localhost:5001",                 // Issuer (Your service)
            sub = "user_987654321",                         // Subject (The unique user ID)
            aud = "my_learning_client_app",                 // Audience (The Client ID)
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(), // Expiration time
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),             // Issued at time
            name = "Jane Doe",                              // Profile data
            email = "jane.doe@example.com"
        };

        // 3. Define the JWT Header
        var headerObj = new
        {
            alg = "RS256", // Algorithm used for signing
            typ = "JWT"    // Token type
        };

        // 4. Serialize and Base64Url Encode the Header and Payload
        string headerJson = JsonSerializer.Serialize(headerObj);
        string payloadJson = JsonSerializer.Serialize(payloadObj);

        string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        // 5. Construct the Data to Sign
        // A JWT signature is calculated over: "encodedHeader.encodedPayload"
        string stringToSign = $"{encodedHeader}.{encodedPayload}";
        byte[] bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

        // 6. Sign the data using the Private RSA Key
        byte[] signatureBytes = rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        string encodedSignature = Base64UrlEncode(signatureBytes);

        // 7. Combine them into the final JWT string!
        string jwt = $"{stringToSign}.{encodedSignature}";

        Console.WriteLine("=== YOUR SIGNED OIDC ID TOKEN ===");
        Console.WriteLine(jwt);
        Console.WriteLine("\nCopy the token above and paste it into https://jwt.io to inspect it!");
    }

    // JWT uses Base64Url encoding, which strips padding (=) and replaces characters (+ and /) 
    // so the token safely fits inside URLs and HTTP headers.
    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace("=", "")
            .Replace("+", "-")
            .Replace("/", "_");
    }
}
