// Where the IdP keeps its state. None keeps everything in memory (a restart forgets it all), which is fine for development.
enum PersistenceProvider { None, Sqlite, SqlServer }

class PersistenceOptions
{
    public PersistenceProvider Provider { get; set; } = PersistenceProvider.None;
    public string? ConnectionString { get; set; }

    // 32 random bytes, base64. Protects the signing key stored in the database. Supply it through an environment variable or a secret store.
    public string? EncryptionKey { get; set; }

    public bool AutoMigrate { get; set; } = true;
    public int SigningKeyRotationDays { get; set; } = 90;
    public int SigningKeyRetentionDays { get; set; } = 7;
    public int CleanupIntervalSeconds { get; set; } = 600;
}

// A client that is fixed in configuration, as opposed to one that registered itself through /register
class ClientOptions
{
    public string ClientId { get; set; } = "";
    public string[] RedirectUris { get; set; } = [];
    public string[] PostLogoutRedirectUris { get; set; } = [];
}
