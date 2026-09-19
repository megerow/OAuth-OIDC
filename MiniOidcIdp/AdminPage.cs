using System.Net;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;

// Server-rendered HTML for /admin/roles. Every dynamic value goes through Html() because group names come from the directory.
static class AdminPage
{
    public static string Render(IdpMode mode, IReadOnlyList<UserReport> users, IReadOnlyList<RoleMapping> mappings, bool canEdit, string? adminGroup, AntiforgeryTokenSet tokens, string? notice)
    {
        static string Html(string? s) => WebUtility.HtmlEncode(s ?? "");

        string tokenField = $"<input type='hidden' name='{Html(tokens.FormFieldName)}' value='{Html(tokens.RequestToken)}' />";
        var sb = new StringBuilder();

        sb.Append(@"<html><head><title>IdP roles</title><style>
            body { font-family: sans-serif; max-width: 960px; margin: 30px auto; padding: 0 16px; }
            table { border-collapse: collapse; width: 100%; margin: 8px 0 24px; }
            th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }
            th { background: #f2f2f2; }
            .role { display: inline-block; background: #0078d4; color: white; border-radius: 10px; padding: 1px 10px; margin-right: 4px; }
            .yes { color: #107c10; font-weight: bold; }
            .notice { background: #fff4ce; border: 1px solid #e8c84a; padding: 8px 12px; border-radius: 4px; }
            code { background: #f2f2f2; padding: 1px 4px; }
            form.inline { display: inline; }
            input[type=text] { padding: 4px; }
        </style></head><body>");

        sb.Append("<h1>Roles and group mappings</h1>");
        sb.Append($"<p>Authentication mode: <b>{Html(mode.ToString())}</b>. Roles are worked out at sign-in, so a change only affects new sign-ins. Tokens already issued keep their old roles until they expire.</p>");

        if (!string.IsNullOrEmpty(notice))
        {
            sb.Append($"<p class='notice'>{Html(notice)}</p>");
        }

        sb.Append("<h2>Roles returned by the IdP</h2>");
        foreach (var user in users)
        {
            sb.Append($"<h3>{Html(user.Name)} <small>({Html(user.Account)})</small></h3>");
            sb.Append($"<p>Token <code>sub</code>: <code>{Html(user.Subject)}</code></p>");
            sb.Append("<p>Roles in the token: ");
            sb.Append(user.Roles.Length == 0
                ? "<i>none</i>"
                : string.Join(" ", user.Roles.Select(r => $"<span class='role'>{Html(r)}</span>")));
            sb.Append("</p>");

            sb.Append("<table><tr><th>Group</th><th>SID</th><th>Mapped to</th>");
            sb.Append(canEdit ? "<th>Map this group to a role</th></tr>" : "</tr>");
            foreach (var group in user.Groups)
            {
                string key = group.Name ?? group.Sid ?? "";
                var mappedRoles = mappings
                    .Where(m => string.Equals(m.Group, group.Name, StringComparison.OrdinalIgnoreCase) || string.Equals(m.Group, group.Sid, StringComparison.OrdinalIgnoreCase))
                    .Select(m => m.Role)
                    .ToList();

                sb.Append($"<tr><td>{Html(group.Name ?? "(name not resolved)")}</td><td><code>{Html(group.Sid)}</code></td>");
                sb.Append($"<td>{(mappedRoles.Count == 0 ? "" : string.Join(" ", mappedRoles.Select(r => $"<span class='role'>{Html(r)}</span>")))}</td>");
                if (canEdit)
                {
                    sb.Append($@"<td><form class='inline' method='post' action='/admin/roles/mappings'>{tokenField}
                        <input type='hidden' name='group' value='{Html(key)}' />
                        <input type='text' name='role' placeholder='Role name' required />
                        <button type='submit'>Add</button></form></td>");
                }
                sb.Append("</tr>");
            }
            sb.Append("</table>");
        }

        sb.Append("<h2>Group to role mappings</h2>");
        sb.Append("<table><tr><th>Group (name or SID)</th><th>Role</th>");
        sb.Append(canEdit ? "<th></th></tr>" : "</tr>");
        foreach (var mapping in mappings)
        {
            sb.Append($"<tr><td>{Html(mapping.Group)}</td><td><span class='role'>{Html(mapping.Role)}</span></td>");
            if (canEdit)
            {
                sb.Append($@"<td><form class='inline' method='post' action='/admin/roles/mappings/delete'>{tokenField}
                    <input type='hidden' name='group' value='{Html(mapping.Group)}' />
                    <input type='hidden' name='role' value='{Html(mapping.Role)}' />
                    <button type='submit'>Remove</button></form></td>");
            }
            sb.Append("</tr>");
        }
        sb.Append("</table>");

        if (canEdit)
        {
            sb.Append($@"<h3>Add a mapping</h3>
                <form method='post' action='/admin/roles/mappings'>{tokenField}
                    <input type='text' name='group' placeholder='DOMAIN\Group or SID' size='40' required />
                    <input type='text' name='role' placeholder='Role name' required />
                    <button type='submit'>Add</button>
                </form>");
        }
        else
        {
            sb.Append(string.IsNullOrWhiteSpace(adminGroup)
                ? "<p><i>Editing is disabled: no <code>Idp:AdminGroup</code> is configured.</i></p>"
                : $"<p><i>Editing needs membership in <code>{Html(adminGroup)}</code>.</i></p>");
        }

        sb.Append("</body></html>");
        return sb.ToString();
    }
}
