using System.Text.Json;
using Microsoft.EntityFrameworkCore;

// Database-backed stores. Every operation uses its own short-lived context, and every "only one caller may win" step is a single
// UPDATE or DELETE whose WHERE clause holds the whole condition, so two IdP nodes racing for the same code or token cannot both succeed.

sealed class SqlClientStore(StaticClients staticClients, IDbContextFactory<IdpDbContext> factory) : IClientStore
{
    public async Task<ClientInfo?> FindAsync(string clientId)
    {
        var fixedClient = staticClients.Find(clientId);
        if (fixedClient != null)
        {
            return fixedClient;
        }

        await using var db = await factory.CreateDbContextAsync();
        var row = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        return row == null
            ? null
            : new ClientInfo(row.ClientId, JsonSerializer.Deserialize<string[]>(row.RedirectUrisJson) ?? [], JsonSerializer.Deserialize<string[]>(row.PostLogoutRedirectUrisJson) ?? []);
    }

    public async Task<bool> TryRegisterAsync(ClientInfo client, string? clientName, int maxDynamicClients)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (await db.Clients.CountAsync() >= maxDynamicClients)
        {
            return false;
        }

        db.Clients.Add(new ClientRow
        {
            ClientId = client.ClientId,
            Name = clientName,
            RedirectUrisJson = JsonSerializer.Serialize(client.RedirectUris),
            PostLogoutRedirectUrisJson = JsonSerializer.Serialize(client.PostLogoutRedirectUris),
            CreatedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });
        await db.SaveChangesAsync();
        return true;
    }
}

sealed class SqlAuthorizationCodeStore(IDbContextFactory<IdpDbContext> factory) : IAuthorizationCodeStore
{
    public async Task SaveAsync(string code, AuthFlowSession session, DateTimeOffset expiresAt)
    {
        await using var db = await factory.CreateDbContextAsync();
        db.AuthorizationCodes.Add(new AuthorizationCodeRow
        {
            CodeHash = TokenHash.Of(code),
            SessionJson = SessionJson.Write(session),
            ExpiresAtUnix = expiresAt.ToUnixTimeSeconds()
        });
        await db.SaveChangesAsync();
    }

    public async Task<AuthFlowSession?> FindAsync(string code)
    {
        byte[] hash = TokenHash.Of(code);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        await using var db = await factory.CreateDbContextAsync();
        string? json = await db.AuthorizationCodes.AsNoTracking()
            .Where(r => r.CodeHash == hash && r.ExpiresAtUnix > now)
            .Select(r => r.SessionJson)
            .FirstOrDefaultAsync();
        return json == null ? null : SessionJson.Read(json);
    }

    public async Task<bool> ConsumeAsync(string code)
    {
        byte[] hash = TokenHash.Of(code);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        await using var db = await factory.CreateDbContextAsync();
        return await db.AuthorizationCodes.Where(r => r.CodeHash == hash && r.ExpiresAtUnix > now).ExecuteDeleteAsync() == 1;
    }

    public async Task<int> PurgeExpiredAsync()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await using var db = await factory.CreateDbContextAsync();
        return await db.AuthorizationCodes.Where(r => r.ExpiresAtUnix <= now).ExecuteDeleteAsync();
    }
}

sealed class SqlRefreshTokenStore(IDbContextFactory<IdpDbContext> factory) : IRefreshTokenStore
{
    public async Task SaveAsync(string token, AuthFlowSession session, string familyId, DateTimeOffset familyCreatedAt, DateTimeOffset expiresAt)
    {
        await using var db = await factory.CreateDbContextAsync();
        db.RefreshTokens.Add(new RefreshTokenRow
        {
            TokenHash = TokenHash.Of(token),
            FamilyId = familyId,
            Subject = session.Subject,
            SessionJson = SessionJson.Write(session),
            IssuedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FamilyCreatedAtUnix = familyCreatedAt.ToUnixTimeSeconds(),
            ExpiresAtUnix = expiresAt.ToUnixTimeSeconds()
        });
        await db.SaveChangesAsync();
    }

    public async Task<RefreshLookup?> FindAsync(string token)
    {
        byte[] hash = TokenHash.Of(token);
        await using var db = await factory.CreateDbContextAsync();
        var row = await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(r => r.TokenHash == hash);
        return row == null
            ? null
            : new RefreshLookup(SessionJson.Read(row.SessionJson), row.FamilyId, DateTimeOffset.FromUnixTimeSeconds(row.ExpiresAtUnix), DateTimeOffset.FromUnixTimeSeconds(row.FamilyCreatedAtUnix), row.Used);
    }

    public async Task<bool> TryMarkUsedAsync(string token)
    {
        byte[] hash = TokenHash.Of(token);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        await using var db = await factory.CreateDbContextAsync();
        return await db.RefreshTokens
            .Where(r => r.TokenHash == hash && !r.Used && r.ExpiresAtUnix > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Used, true)) == 1;
    }

    public async Task RevokeFamilyAsync(string familyId)
    {
        await using var db = await factory.CreateDbContextAsync();
        await db.RefreshTokens.Where(r => r.FamilyId == familyId).ExecuteDeleteAsync();
    }

    public async Task<int> RevokeBySubjectAsync(string subject)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await using var db = await factory.CreateDbContextAsync();
        int liveSignIns = await db.RefreshTokens.CountAsync(r => r.Subject == subject && !r.Used && r.ExpiresAtUnix > now);
        await db.RefreshTokens.Where(r => r.Subject == subject).ExecuteDeleteAsync();
        return liveSignIns;
    }

    public async Task<IReadOnlyList<ActiveSession>> ListActiveSessionsAsync()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await using var db = await factory.CreateDbContextAsync();
        var live = await db.RefreshTokens.AsNoTracking()
            .Where(r => !r.Used && r.ExpiresAtUnix > now)
            .Select(r => new { r.Subject, r.SessionJson, r.IssuedAtUnix })
            .ToListAsync();

        return live
            .GroupBy(r => r.Subject)
            .Select(g =>
            {
                var session = SessionJson.Read(g.First().SessionJson);
                return new ActiveSession(g.Key, session.Account, session.Name, g.Count(), DateTimeOffset.FromUnixTimeSeconds(g.Max(r => r.IssuedAtUnix)));
            })
            .OrderBy(s => s.Account)
            .ToList();
    }

    public async Task<int> PurgeExpiredAsync()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await using var db = await factory.CreateDbContextAsync();
        return await db.RefreshTokens.Where(r => r.ExpiresAtUnix <= now).ExecuteDeleteAsync();
    }
}

sealed class SqlRoleMappingStore(IDbContextFactory<IdpDbContext> factory) : IRoleMappingStore
{
    const string SeededMarker = "RoleMappingsSeeded";

    // Copies the mappings from configuration into an empty database exactly once. The marker, not "the table is empty",
    // decides, so an administrator who deletes every mapping does not get the defaults back after a restart.
    public async Task SeedAsync(IEnumerable<RoleMapping> configured)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (await db.Settings.AnyAsync(s => s.Key == SeededMarker))
        {
            return;
        }

        var unique = configured
            .Where(m => RoleMappingRules.Validate(m) == null)
            .GroupBy(m => (m.Group.ToLowerInvariant(), m.Role))
            .Select(g => g.First());

        db.Settings.Add(new SettingRow { Key = SeededMarker, Value = "1" });
        db.RoleMappings.AddRange(unique.Select(m => new RoleMappingRow { GroupName = m.Group, Role = m.Role }));

        try
        {
            await db.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // Another node seeded at the same moment
            await using var check = await factory.CreateDbContextAsync();
            if (!await check.Settings.AnyAsync(s => s.Key == SeededMarker))
            {
                throw;
            }
        }
    }

    public async Task<IReadOnlyList<RoleMapping>> SnapshotAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.RoleMappings.AsNoTracking()
            .OrderBy(r => r.Id)
            .Select(r => new RoleMapping { Group = r.GroupName, Role = r.Role })
            .ToListAsync();
    }

    public async Task<string?> AddAsync(RoleMapping mapping)
    {
        var error = RoleMappingRules.Validate(mapping);
        if (error != null)
        {
            return error;
        }

        await using var db = await factory.CreateDbContextAsync();
        if (await ExistsAsync(db, mapping))
        {
            return "That mapping already exists.";
        }

        db.RoleMappings.Add(new RoleMappingRow { GroupName = mapping.Group, Role = mapping.Role });
        try
        {
            await db.SaveChangesAsync();
            return null;
        }
        catch (DbUpdateException)
        {
            // The unique index caught a duplicate that another node added first
            await using var check = await factory.CreateDbContextAsync();
            if (await ExistsAsync(check, mapping))
            {
                return "That mapping already exists.";
            }
            throw;
        }
    }

    public async Task<string?> RemoveAsync(RoleMapping mapping)
    {
        await using var db = await factory.CreateDbContextAsync();

        // Group names are compared without regard to case, as when roles are worked out. SQLite would otherwise be case-sensitive here.
        var sameRole = await db.RoleMappings.Where(r => r.Role == mapping.Role).ToListAsync();
        var matches = sameRole.Where(r => string.Equals(r.GroupName, mapping.Group, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0)
        {
            return "That mapping no longer exists.";
        }

        db.RoleMappings.RemoveRange(matches);
        await db.SaveChangesAsync();
        return null;
    }

    static async Task<bool> ExistsAsync(IdpDbContext db, RoleMapping mapping) =>
        (await db.RoleMappings.AsNoTracking().Where(r => r.Role == mapping.Role).Select(r => r.GroupName).ToListAsync())
            .Any(g => string.Equals(g, mapping.Group, StringComparison.OrdinalIgnoreCase));
}
