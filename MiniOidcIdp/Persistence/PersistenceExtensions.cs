using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

static class PersistenceExtensions
{
    // Chooses the stores. With Provider=None everything stays in memory and nothing is written anywhere except the role-mappings file.
    public static PersistenceOptions AddIdpPersistence(this IServiceCollection services, IConfiguration configuration, IdpOptions idp)
    {
        var options = configuration.GetSection("Persistence").Get<PersistenceOptions>() ?? new PersistenceOptions();
        services.AddSingleton(options);
        services.AddSingleton(new StaticClients(idp.Clients));

        if (options.Provider == PersistenceProvider.None)
        {
            string mappingsFile = idp.MappingsFile
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MiniOidc", "role-mappings.json");

            services.AddSingleton<IClientStore, MemoryClientStore>();
            services.AddSingleton<IAuthorizationCodeStore, MemoryAuthorizationCodeStore>();
            services.AddSingleton<IRefreshTokenStore, MemoryRefreshTokenStore>();
            services.AddSingleton<IRoleMappingStore>(new FileRoleMappingStore(idp.RoleMappings, mappingsFile));
            services.AddSingleton<ISigningKeyProvider, MemorySigningKeyProvider>();
        }
        else
        {
            if (string.IsNullOrWhiteSpace(options.ConnectionString))
            {
                throw new InvalidOperationException($"Persistence:ConnectionString is required when Persistence:Provider is {options.Provider}.");
            }

            // Fails at startup, with a clear message, when the key is missing or the wrong size
            services.AddSingleton(new AesGcmProtector(options.EncryptionKey));

            if (options.Provider == PersistenceProvider.Sqlite)
            {
                string connectionString = PrepareSqliteConnectionString(options.ConnectionString);
                services.AddDbContextFactory<SqliteIdpDbContext>(o => o.UseSqlite(connectionString));
                services.AddSingleton<IDbContextFactory<IdpDbContext>, DerivedContextFactory<SqliteIdpDbContext>>();
                services.AddDataProtection().SetApplicationName("MiniOidcIdp").PersistKeysToDbContext<SqliteIdpDbContext>();
            }
            else
            {
                services.AddDbContextFactory<SqlServerIdpDbContext>(o => o.UseSqlServer(options.ConnectionString));
                services.AddSingleton<IDbContextFactory<IdpDbContext>, DerivedContextFactory<SqlServerIdpDbContext>>();
                services.AddDataProtection().SetApplicationName("MiniOidcIdp").PersistKeysToDbContext<SqlServerIdpDbContext>();
            }

            services.AddSingleton<IClientStore, SqlClientStore>();
            services.AddSingleton<IAuthorizationCodeStore, SqlAuthorizationCodeStore>();
            services.AddSingleton<IRefreshTokenStore, SqlRefreshTokenStore>();
            services.AddSingleton<SqlRoleMappingStore>();
            services.AddSingleton<IRoleMappingStore>(sp => sp.GetRequiredService<SqlRoleMappingStore>());
            services.AddSingleton<ISigningKeyProvider, SqlSigningKeyProvider>();
        }

        services.AddHostedService<CleanupService>();
        return options;
    }

    // Creates or updates the schema, seeds the role mappings, and makes sure a signing key exists.
    // Anything wrong (unreachable database, pending migrations, wrong encryption key) stops the IdP here.
    public static async Task InitializeIdpPersistenceAsync(this IServiceProvider services, IdpOptions idp)
    {
        var options = services.GetRequiredService<PersistenceOptions>();

        if (options.Provider != PersistenceProvider.None)
        {
            var factory = services.GetRequiredService<IDbContextFactory<IdpDbContext>>();
            await using (var db = await factory.CreateDbContextAsync())
            {
                if (options.Provider == PersistenceProvider.Sqlite)
                {
                    // Write-ahead logging lets several processes read while one writes. It is stored in the file, so this only needs to run once.
                    var connection = db.Database.GetDbConnection();
                    await connection.OpenAsync();
                    await using var command = connection.CreateCommand();
                    command.CommandText = "PRAGMA journal_mode=WAL;";
                    await command.ExecuteScalarAsync();
                }

                if (options.AutoMigrate)
                {
                    await db.Database.MigrateAsync();
                }
                else
                {
                    var pending = (await db.Database.GetPendingMigrationsAsync()).ToList();
                    if (pending.Count > 0)
                    {
                        throw new InvalidOperationException($"The database schema is behind ({pending.Count} pending migration(s): {string.Join(", ", pending)}). Apply the migration script, or set Persistence:AutoMigrate to true.");
                    }
                }
            }

            await services.GetRequiredService<SqlRoleMappingStore>().SeedAsync(idp.RoleMappings);
        }

        await services.GetRequiredService<ISigningKeyProvider>().MaintainAsync();
    }

    // Waits for a busy database instead of failing at once, which matters when two IdP processes share one file
    static string PrepareSqliteConnectionString(string connectionString)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        if (!connectionString.Contains("Default Timeout", StringComparison.OrdinalIgnoreCase))
        {
            builder.DefaultTimeout = 30;
        }

        string? directory = Path.GetDirectoryName(Path.GetFullPath(builder.DataSource));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return builder.ToString();
    }
}
