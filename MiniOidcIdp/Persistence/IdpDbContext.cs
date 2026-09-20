using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

// Times are stored as Unix seconds in a long: SQLite cannot compare DateTimeOffset values inside a query.
class SigningKeyRow
{
    public string Kid { get; set; } = "";
    public long CreatedAtUnix { get; set; }
    public byte[] EncryptedPrivateKey { get; set; } = [];
}

class ClientRow
{
    public string ClientId { get; set; } = "";
    public string? Name { get; set; }
    public string RedirectUrisJson { get; set; } = "[]";
    public string PostLogoutRedirectUrisJson { get; set; } = "[]";
    public long CreatedAtUnix { get; set; }
}

class AuthorizationCodeRow
{
    public byte[] CodeHash { get; set; } = [];
    public string SessionJson { get; set; } = "";
    public long ExpiresAtUnix { get; set; }
}

class RefreshTokenRow
{
    public byte[] TokenHash { get; set; } = [];
    public string FamilyId { get; set; } = "";
    public string Subject { get; set; } = "";
    public string SessionJson { get; set; } = "";
    public long IssuedAtUnix { get; set; }
    public long FamilyCreatedAtUnix { get; set; }
    public long ExpiresAtUnix { get; set; }
    public bool Used { get; set; }
}

class RoleMappingRow
{
    public int Id { get; set; }
    public string GroupName { get; set; } = "";
    public string Role { get; set; } = "";
}

class SettingRow
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}

// One model for both providers. Each provider has its own derived context so that it gets its own set of migrations.
abstract class IdpDbContext(DbContextOptions options) : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<SigningKeyRow> SigningKeys => Set<SigningKeyRow>();
    public DbSet<ClientRow> Clients => Set<ClientRow>();
    public DbSet<AuthorizationCodeRow> AuthorizationCodes => Set<AuthorizationCodeRow>();
    public DbSet<RefreshTokenRow> RefreshTokens => Set<RefreshTokenRow>();
    public DbSet<RoleMappingRow> RoleMappings => Set<RoleMappingRow>();
    public DbSet<SettingRow> Settings => Set<SettingRow>();

    // Keys the framework uses for anti-forgery tokens, kept here so that every IdP node shares them
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SigningKeyRow>(e =>
        {
            e.HasKey(r => r.Kid);
            e.Property(r => r.Kid).HasMaxLength(64);
            e.Property(r => r.EncryptedPrivateKey).IsRequired();
        });

        modelBuilder.Entity<ClientRow>(e =>
        {
            e.HasKey(r => r.ClientId);
            e.Property(r => r.ClientId).HasMaxLength(200);
            e.Property(r => r.Name).HasMaxLength(200);
        });

        modelBuilder.Entity<AuthorizationCodeRow>(e =>
        {
            e.HasKey(r => r.CodeHash);
            e.Property(r => r.CodeHash).HasMaxLength(32);
            e.HasIndex(r => r.ExpiresAtUnix);
        });

        modelBuilder.Entity<RefreshTokenRow>(e =>
        {
            e.HasKey(r => r.TokenHash);
            e.Property(r => r.TokenHash).HasMaxLength(32);
            e.Property(r => r.FamilyId).HasMaxLength(64);
            e.Property(r => r.Subject).HasMaxLength(256);
            e.HasIndex(r => r.FamilyId);
            e.HasIndex(r => r.Subject);
            e.HasIndex(r => r.ExpiresAtUnix);
        });

        modelBuilder.Entity<RoleMappingRow>(e =>
        {
            e.Property(r => r.GroupName).HasMaxLength(256);
            e.Property(r => r.Role).HasMaxLength(64);
            e.HasIndex(r => new { r.GroupName, r.Role }).IsUnique();
        });

        modelBuilder.Entity<SettingRow>(e =>
        {
            e.HasKey(r => r.Key);
            e.Property(r => r.Key).HasMaxLength(100);
            e.Property(r => r.Value).HasMaxLength(400);
        });
    }
}

class SqliteIdpDbContext(DbContextOptions<SqliteIdpDbContext> options) : IdpDbContext(options);

class SqlServerIdpDbContext(DbContextOptions<SqlServerIdpDbContext> options) : IdpDbContext(options);

// Used only by `dotnet ef` to create migrations. The connection strings are never contacted.
class SqliteDesignTimeFactory : IDesignTimeDbContextFactory<SqliteIdpDbContext>
{
    public SqliteIdpDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<SqliteIdpDbContext>().UseSqlite("Data Source=design-time.db").Options);
}

class SqlServerDesignTimeFactory : IDesignTimeDbContextFactory<SqlServerIdpDbContext>
{
    public SqlServerIdpDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<SqlServerIdpDbContext>().UseSqlServer("Server=design-time;Database=MiniOidcIdp;Integrated Security=true;TrustServerCertificate=true").Options);
}

// Lets the stores ask for the base context type while the container builds the provider-specific one
sealed class DerivedContextFactory<TContext>(IDbContextFactory<TContext> inner) : IDbContextFactory<IdpDbContext> where TContext : IdpDbContext
{
    public IdpDbContext CreateDbContext() => inner.CreateDbContext();

    public async Task<IdpDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
        await inner.CreateDbContextAsync(cancellationToken);
}
