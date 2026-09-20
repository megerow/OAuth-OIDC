// Housekeeping that runs on a timer: removes expired codes and refresh tokens, and lets the signing-key provider rotate keys and
// delete old ones. It also runs in memory-only mode, so code expiry behaves the same either way.
sealed class CleanupService(IAuthorizationCodeStore codes, IRefreshTokenStore refreshTokens, ISigningKeyProvider signingKeys, PersistenceOptions options, ILogger<CleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, options.CleanupIntervalSeconds)));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            // One failed pass (for example a brief database outage) must not stop the ones after it
            try
            {
                int expiredCodes = await codes.PurgeExpiredAsync();
                int expiredTokens = await refreshTokens.PurgeExpiredAsync();
                await signingKeys.MaintainAsync();

                if (expiredCodes + expiredTokens > 0)
                {
                    logger.LogInformation("Cleanup removed {Codes} expired code(s) and {Tokens} expired refresh token(s)", expiredCodes, expiredTokens);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Cleanup pass failed; it will run again at the next interval");
            }
        }
    }
}
