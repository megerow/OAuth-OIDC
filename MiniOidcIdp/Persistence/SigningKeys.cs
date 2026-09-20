using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

record SigningKey(string Kid, RSA Rsa);

// The public half of a key, as it appears in the JWKS document (modulus and exponent, base64url)
record PublishedKey(string Kid, string Modulus, string Exponent);

interface ISigningKeyProvider
{
    // The key new tokens are signed with
    Task<SigningKey> GetActiveAsync();

    // Every key a resource server might need to check a token that is still valid
    Task<IReadOnlyList<PublishedKey>> GetPublishedAsync();

    // Used to check tokens the IdP itself issued, for example an id_token_hint at logout
    Task<RSA?> GetVerificationKeyAsync(string kid);

    // Creates the first key, rotates when the newest is due, and removes keys past their retention. Safe to call often.
    Task MaintainAsync();
}

static class Base64Url
{
    public static string Encode(byte[] input) => Convert.ToBase64String(input).Replace("=", "").Replace("+", "-").Replace("/", "_");

    public static byte[] Decode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded + new string('=', (4 - padded.Length % 4) % 4));
    }
}

static class KeyId
{
    // Derived from the public key, so different keys never share an id
    public static string Of(byte[] modulus) => Base64Url.Encode(SHA256.HashData(modulus))[..16];
}

// Development: one key made at startup and forgotten at shutdown, as before
sealed class MemorySigningKeyProvider : ISigningKeyProvider
{
    readonly SigningKey key;
    readonly PublishedKey published;

    public MemorySigningKeyProvider()
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        string kid = KeyId.Of(parameters.Modulus!);
        key = new SigningKey(kid, rsa);
        published = new PublishedKey(kid, Base64Url.Encode(parameters.Modulus!), Base64Url.Encode(parameters.Exponent!));
    }

    public Task<SigningKey> GetActiveAsync() => Task.FromResult(key);
    public Task<IReadOnlyList<PublishedKey>> GetPublishedAsync() => Task.FromResult<IReadOnlyList<PublishedKey>>([published]);
    public Task<RSA?> GetVerificationKeyAsync(string kid) => Task.FromResult<RSA?>(kid == key.Kid ? key.Rsa : null);
    public Task MaintainAsync() => Task.CompletedTask;
}

// Keys live in the database with the private half encrypted. Several IdP nodes share them, so:
//  - the JWKS lists every stored key, so a token signed by any node can be checked by any resource server;
//  - a brand new key is not used for signing until other nodes have had time to publish it;
//  - rotation only adds a key. Older keys stay published for the retention period, then are deleted.
sealed class SqlSigningKeyProvider(IDbContextFactory<IdpDbContext> factory, AesGcmProtector protector, PersistenceOptions options, ILogger<SqlSigningKeyProvider> logger) : ISigningKeyProvider
{
    // How long a node trusts its list of keys, and how long a new key waits before it starts signing (twice the cache time)
    static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(60);
    static readonly TimeSpan ActivationDelay = TimeSpan.FromSeconds(120);
    static readonly TimeSpan MinimumReloadOnMiss = TimeSpan.FromSeconds(5);

    sealed record CachedKey(string Kid, DateTimeOffset CreatedAt, RSA Rsa, PublishedKey Published);

    readonly SemaphoreSlim gate = new(1, 1);
    readonly Dictionary<string, RSA> rsaByKid = new();
    volatile IReadOnlyList<CachedKey> cache = [];
    DateTimeOffset loadedAt = DateTimeOffset.MinValue;

    public async Task<SigningKey> GetActiveAsync()
    {
        var keys = await KeysAsync();
        if (keys.Count == 0)
        {
            await MaintainAsync();
            keys = await KeysAsync();
        }

        // Newest first. A key created moments ago may not be published by the other nodes yet, so the previous one keeps signing.
        var chosen = keys.Count > 1 && DateTimeOffset.UtcNow - keys[0].CreatedAt < ActivationDelay ? keys[1] : keys[0];
        return new SigningKey(chosen.Kid, chosen.Rsa);
    }

    // Read more often than the signing list, so a key another node has just created is published within seconds
    public async Task<IReadOnlyList<PublishedKey>> GetPublishedAsync() =>
        (await KeysAsync(MinimumReloadOnMiss)).Select(k => k.Published).ToList();

    public async Task<RSA?> GetVerificationKeyAsync(string kid)
    {
        var found = (await KeysAsync()).FirstOrDefault(k => k.Kid == kid);
        if (found == null && DateTimeOffset.UtcNow - loadedAt > MinimumReloadOnMiss)
        {
            // Possibly a key another node just created
            found = (await ReloadAsync()).FirstOrDefault(k => k.Kid == kid);
        }
        return found?.Rsa;
    }

    public async Task MaintainAsync()
    {
        await gate.WaitAsync();
        try
        {
            // Loading decrypts every stored key, so a wrong encryption key stops the IdP here rather than at the first sign-in
            var keys = await LoadAsync();
            var now = DateTimeOffset.UtcNow;
            var rotateAfter = TimeSpan.FromDays(Math.Max(1, options.SigningKeyRotationDays));

            if (keys.Count == 0 || now - keys[0].CreatedAt >= rotateAfter)
            {
                await CreateKeyIfStillDueAsync(now, rotateAfter);
            }

            await PurgeOldKeysAsync(now, rotateAfter + TimeSpan.FromDays(Math.Max(0, options.SigningKeyRetentionDays)));
            await LoadAsync();
        }
        finally
        {
            gate.Release();
        }
    }

    async Task<IReadOnlyList<CachedKey>> KeysAsync(TimeSpan? maxAge = null)
    {
        if (cache.Count > 0 && DateTimeOffset.UtcNow - loadedAt < (maxAge ?? CacheLifetime))
        {
            return cache;
        }

        return await ReloadAsync();
    }

    async Task<IReadOnlyList<CachedKey>> ReloadAsync()
    {
        await gate.WaitAsync();
        try
        {
            return await LoadAsync();
        }
        finally
        {
            gate.Release();
        }
    }

    // Callers hold the gate
    async Task<IReadOnlyList<CachedKey>> LoadAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        var rows = await db.SigningKeys.AsNoTracking().OrderByDescending(k => k.CreatedAtUnix).ToListAsync();

        var keys = new List<CachedKey>(rows.Count);
        foreach (var row in rows)
        {
            // One RSA object per key, reused across reloads because requests may still be signing with it
            if (!rsaByKid.TryGetValue(row.Kid, out var rsa))
            {
                rsa = RSA.Create();
                try
                {
                    rsa.ImportPkcs8PrivateKey(protector.Unprotect(row.EncryptedPrivateKey, row.Kid), out _);
                }
                catch (CryptographicException ex)
                {
                    throw new InvalidOperationException(
                        $"The signing key {row.Kid} stored in the database cannot be decrypted. Persistence:EncryptionKey is not the key this database was created with. " +
                        "Use the original key. Do not replace it, or every token this IdP has issued would stop validating.", ex);
                }
                rsaByKid[row.Kid] = rsa;
            }

            var parameters = rsa.ExportParameters(false);
            keys.Add(new CachedKey(row.Kid, DateTimeOffset.FromUnixTimeSeconds(row.CreatedAtUnix), rsa,
                new PublishedKey(row.Kid, Base64Url.Encode(parameters.Modulus!), Base64Url.Encode(parameters.Exponent!))));
        }

        cache = keys;
        loadedAt = DateTimeOffset.UtcNow;
        return keys;
    }

    async Task CreateKeyIfStillDueAsync(DateTimeOffset now, TimeSpan rotateAfter)
    {
        await using var db = await factory.CreateDbContextAsync();

        // Another node may have rotated a moment ago, so look at the newest key again before adding one
        long? newest = await db.SigningKeys.MaxAsync(k => (long?)k.CreatedAtUnix);
        if (newest != null && now - DateTimeOffset.FromUnixTimeSeconds(newest.Value) < rotateAfter)
        {
            return;
        }

        using var rsa = RSA.Create(2048);
        string kid = KeyId.Of(rsa.ExportParameters(false).Modulus!);
        db.SigningKeys.Add(new SigningKeyRow
        {
            Kid = kid,
            CreatedAtUnix = now.ToUnixTimeSeconds(),
            EncryptedPrivateKey = protector.Protect(rsa.ExportPkcs8PrivateKey(), kid)
        });
        await db.SaveChangesAsync();
        logger.LogInformation("Created signing key {Kid}", kid);
    }

    async Task PurgeOldKeysAsync(DateTimeOffset now, TimeSpan keepFor)
    {
        await using var db = await factory.CreateDbContextAsync();
        string? newestKid = await db.SigningKeys.OrderByDescending(k => k.CreatedAtUnix).Select(k => k.Kid).FirstOrDefaultAsync();
        long cutoff = (now - keepFor).ToUnixTimeSeconds();

        int removed = await db.SigningKeys.Where(k => k.CreatedAtUnix < cutoff && k.Kid != newestKid).ExecuteDeleteAsync();
        if (removed > 0)
        {
            logger.LogInformation("Removed {Count} signing key(s) past their retention", removed);
        }
    }
}
