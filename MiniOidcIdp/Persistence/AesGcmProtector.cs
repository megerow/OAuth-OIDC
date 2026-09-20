using System.Security.Cryptography;
using System.Text;

// Encrypts small secrets (the IdP's private signing keys) before they are stored.
// Stored form: version (1 byte) | nonce (12) | tag (16) | ciphertext. The key id is authenticated but not encrypted,
// so an encrypted key cannot be moved from one row to another.
sealed class AesGcmProtector
{
    const byte FormatVersion = 1;
    const int NonceSize = 12;
    const int TagSize = 16;

    readonly byte[] key;

    public AesGcmProtector(string? base64Key)
    {
        if (string.IsNullOrWhiteSpace(base64Key))
        {
            throw new InvalidOperationException("Persistence:EncryptionKey is required when a database is used. Generate one with: openssl rand -base64 32");
        }

        try
        {
            key = Convert.FromBase64String(base64Key);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("Persistence:EncryptionKey must be base64.");
        }

        if (key.Length != 32)
        {
            throw new InvalidOperationException($"Persistence:EncryptionKey must decode to exactly 32 bytes (it is {key.Length}).");
        }
    }

    public byte[] Protect(byte[] plaintext, string associatedData)
    {
        var blob = new byte[1 + NonceSize + TagSize + plaintext.Length];
        blob[0] = FormatVersion;
        var nonce = blob.AsSpan(1, NonceSize);
        var tag = blob.AsSpan(1 + NonceSize, TagSize);
        var ciphertext = blob.AsSpan(1 + NonceSize + TagSize);

        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(associatedData));
        return blob;
    }

    public byte[] Unprotect(byte[] blob, string associatedData)
    {
        if (blob.Length < 1 + NonceSize + TagSize || blob[0] != FormatVersion)
        {
            throw new CryptographicException("The stored key is not in a format this version understands.");
        }

        var plaintext = new byte[blob.Length - 1 - NonceSize - TagSize];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(blob.AsSpan(1, NonceSize), blob.AsSpan(1 + NonceSize + TagSize), blob.AsSpan(1 + NonceSize, TagSize), plaintext, Encoding.UTF8.GetBytes(associatedData));
        return plaintext;
    }
}
