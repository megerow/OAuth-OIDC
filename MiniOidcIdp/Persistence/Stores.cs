using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// The state of a sign-in: what an authorization code, and later a refresh token, stands for
record AuthFlowSession(string ClientId, string RedirectUri, string CodeChallenge, string Subject, string Account, string Name, string[] Roles, string? Resource, string? Scope);

record ClientInfo(string ClientId, IReadOnlyList<string> RedirectUris, IReadOnlyList<string> PostLogoutRedirectUris);

// What the IdP knows about a refresh token it issued
record RefreshLookup(AuthFlowSession Session, string FamilyId, DateTimeOffset ExpiresAt, DateTimeOffset FamilyCreatedAt, bool Used);

// A user with live sign-ins, for the admin page
record ActiveSession(string Subject, string Account, string Name, int SignIns, DateTimeOffset LastIssued);

interface IClientStore
{
    Task<ClientInfo?> FindAsync(string clientId);

    // False when the limit on dynamically registered clients has been reached
    Task<bool> TryRegisterAsync(ClientInfo client, string? clientName, int maxDynamicClients);
}

interface IAuthorizationCodeStore
{
    Task SaveAsync(string code, AuthFlowSession session, DateTimeOffset expiresAt);

    // Null when the code is unknown or has expired
    Task<AuthFlowSession?> FindAsync(string code);

    // True for exactly one caller: the one that removed the code
    Task<bool> ConsumeAsync(string code);

    Task<int> PurgeExpiredAsync();
}

interface IRefreshTokenStore
{
    Task SaveAsync(string token, AuthFlowSession session, string familyId, DateTimeOffset familyCreatedAt, DateTimeOffset expiresAt);
    Task<RefreshLookup?> FindAsync(string token);

    // True only for the caller that flipped an unused, unexpired token to used
    Task<bool> TryMarkUsedAsync(string token);

    Task RevokeFamilyAsync(string familyId);

    // Cancels every refresh token for one user and returns how many live sign-ins that ended
    Task<int> RevokeBySubjectAsync(string subject);

    Task<IReadOnlyList<ActiveSession>> ListActiveSessionsAsync();
    Task<int> PurgeExpiredAsync();
}

interface IRoleMappingStore
{
    Task<IReadOnlyList<RoleMapping>> SnapshotAsync();

    // Each returns an error message, or null on success
    Task<string?> AddAsync(RoleMapping mapping);
    Task<string?> RemoveAsync(RoleMapping mapping);
}

// Codes and refresh tokens are looked up by their hash, so a copy of the store never contains a usable secret
static class TokenHash
{
    public static byte[] Of(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
    public static string HexOf(string token) => Convert.ToHexString(Of(token));
}

// Clients that are fixed in configuration. They are never written to a database.
sealed class StaticClients
{
    readonly Dictionary<string, ClientInfo> clients;

    public StaticClients(IEnumerable<ClientOptions> options)
    {
        clients = options
            .Where(c => !string.IsNullOrWhiteSpace(c.ClientId))
            .ToDictionary(c => c.ClientId, c => new ClientInfo(c.ClientId, c.RedirectUris, c.PostLogoutRedirectUris));
    }

    public ClientInfo? Find(string clientId) => clients.GetValueOrDefault(clientId);
}

sealed class MemoryClientStore(StaticClients staticClients) : IClientStore
{
    readonly ConcurrentDictionary<string, ClientInfo> dynamicClients = new();

    public Task<ClientInfo?> FindAsync(string clientId) =>
        Task.FromResult(staticClients.Find(clientId) ?? dynamicClients.GetValueOrDefault(clientId));

    public Task<bool> TryRegisterAsync(ClientInfo client, string? clientName, int maxDynamicClients)
    {
        if (dynamicClients.Count >= maxDynamicClients)
        {
            return Task.FromResult(false);
        }

        dynamicClients[client.ClientId] = client;
        return Task.FromResult(true);
    }
}

sealed class MemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    readonly ConcurrentDictionary<string, (AuthFlowSession Session, DateTimeOffset ExpiresAt)> codes = new();

    public Task SaveAsync(string code, AuthFlowSession session, DateTimeOffset expiresAt)
    {
        codes[TokenHash.HexOf(code)] = (session, expiresAt);
        return Task.CompletedTask;
    }

    public Task<AuthFlowSession?> FindAsync(string code) =>
        Task.FromResult(codes.TryGetValue(TokenHash.HexOf(code), out var entry) && entry.ExpiresAt > DateTimeOffset.UtcNow ? entry.Session : null);

    public Task<bool> ConsumeAsync(string code) =>
        Task.FromResult(codes.TryRemove(TokenHash.HexOf(code), out var entry) && entry.ExpiresAt > DateTimeOffset.UtcNow);

    public Task<int> PurgeExpiredAsync()
    {
        var now = DateTimeOffset.UtcNow;
        int removed = 0;
        foreach (var key in codes.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList())
        {
            removed += codes.TryRemove(key, out _) ? 1 : 0;
        }
        return Task.FromResult(removed);
    }
}

sealed class MemoryRefreshTokenStore : IRefreshTokenStore
{
    sealed class Entry(AuthFlowSession session, string familyId, DateTimeOffset familyCreatedAt, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        public AuthFlowSession Session { get; } = session;
        public string FamilyId { get; } = familyId;
        public DateTimeOffset FamilyCreatedAt { get; } = familyCreatedAt;
        public DateTimeOffset IssuedAt { get; } = issuedAt;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        public bool Used { get; set; }
    }

    // Used tokens stay until they expire so that a replay can be recognised
    readonly ConcurrentDictionary<string, Entry> tokens = new();

    public Task SaveAsync(string token, AuthFlowSession session, string familyId, DateTimeOffset familyCreatedAt, DateTimeOffset expiresAt)
    {
        tokens[TokenHash.HexOf(token)] = new Entry(session, familyId, familyCreatedAt, DateTimeOffset.UtcNow, expiresAt);
        return Task.CompletedTask;
    }

    public Task<RefreshLookup?> FindAsync(string token)
    {
        if (!tokens.TryGetValue(TokenHash.HexOf(token), out var entry))
        {
            return Task.FromResult<RefreshLookup?>(null);
        }

        lock (entry)
        {
            return Task.FromResult<RefreshLookup?>(new RefreshLookup(entry.Session, entry.FamilyId, entry.ExpiresAt, entry.FamilyCreatedAt, entry.Used));
        }
    }

    public Task<bool> TryMarkUsedAsync(string token)
    {
        if (!tokens.TryGetValue(TokenHash.HexOf(token), out var entry))
        {
            return Task.FromResult(false);
        }

        lock (entry)
        {
            if (entry.Used || entry.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                return Task.FromResult(false);
            }

            entry.Used = true;
            return Task.FromResult(true);
        }
    }

    public Task RevokeFamilyAsync(string familyId)
    {
        foreach (var key in tokens.Where(kv => kv.Value.FamilyId == familyId).Select(kv => kv.Key).ToList())
        {
            tokens.TryRemove(key, out _);
        }
        return Task.CompletedTask;
    }

    public Task<int> RevokeBySubjectAsync(string subject)
    {
        var now = DateTimeOffset.UtcNow;
        var ofUser = tokens.Where(kv => kv.Value.Session.Subject == subject).ToList();
        int liveSignIns = ofUser.Count(kv => !kv.Value.Used && kv.Value.ExpiresAt > now);
        foreach (var kv in ofUser)
        {
            tokens.TryRemove(kv.Key, out _);
        }
        return Task.FromResult(liveSignIns);
    }

    public Task<IReadOnlyList<ActiveSession>> ListActiveSessionsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<ActiveSession> sessions = tokens.Values
            .Where(e => !e.Used && e.ExpiresAt > now)
            .GroupBy(e => e.Session.Subject)
            .Select(g => new ActiveSession(g.Key, g.First().Session.Account, g.First().Session.Name, g.Count(), g.Max(e => e.IssuedAt)))
            .OrderBy(s => s.Account)
            .ToList();
        return Task.FromResult(sessions);
    }

    public Task<int> PurgeExpiredAsync()
    {
        var now = DateTimeOffset.UtcNow;
        int removed = 0;
        foreach (var key in tokens.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList())
        {
            removed += tokens.TryRemove(key, out _) ? 1 : 0;
        }
        return Task.FromResult(removed);
    }
}

// The JSON form of a session, used by the database stores
static class SessionJson
{
    public static string Write(AuthFlowSession session) => JsonSerializer.Serialize(session);
    public static AuthFlowSession Read(string json) => JsonSerializer.Deserialize<AuthFlowSession>(json)!;
}
