using System.ComponentModel;
using Microsoft.AspNetCore.Authorization;
using ModelContextProtocol.Server;

[McpServerToolType]
public class DemoTools(IHttpContextAccessor httpContextAccessor)
{
    [McpServerTool(Name = "whoami"), Description("Returns the identity, roles and scopes of the authenticated caller.")]
    public object WhoAmI()
    {
        var user = httpContextAccessor.HttpContext!.User;
        return new
        {
            name = user.FindFirst("name")?.Value,
            subject = user.FindFirst("sub")?.Value,
            roles = user.FindAll("roles").Select(c => c.Value).ToArray(),
            scope = user.FindFirst("scope")?.Value,
            clientId = user.FindFirst("client_id")?.Value
        };
    }

    [McpServerTool(Name = "get_billing_summary"), Description("Returns a mock billing summary. Requires the BillingManager role.")]
    [Authorize(Roles = "BillingManager")]
    public object GetBillingSummary() => new { period = "2026-09", invoicesOutstanding = 3, totalDueUsd = 1284.50m };

    [McpServerTool(Name = "reset_cache"), Description("Pretends to reset the application cache. Requires the Admin role.")]
    [Authorize(Roles = "Admin")]
    public string ResetCache() => "Cache reset (mock).";
}
