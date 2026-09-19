using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

// Where the IdP gets the signed-in user's identity and groups from
enum IdpMode { Persona, WindowsKestrel, WindowsIis }

class IdpOptions
{
    public IdpMode AuthenticationMode { get; set; } = IdpMode.Persona;
    public bool EnableAdminUi { get; set; }
    public string? AdminGroup { get; set; }
    public string? MappingsFile { get; set; }
    public List<RoleMapping> RoleMappings { get; set; } = new();
    public List<Persona> Personas { get; set; } = new();
}

// Maps a group (name such as DOMAIN\Group, or a SID) to an application role that goes into the token
record RoleMapping
{
    public string Group { get; init; } = "";
    public string Role { get; init; } = "";
}

// A fake user for Persona mode (Linux and other non-Windows development)
class Persona
{
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
    public string Name { get; set; } = "";
    public string Sid { get; set; } = "";
    public string[] Groups { get; set; } = [];
}

record GroupInfo(string? Name, string? Sid);

// The signed-in user as the rest of the IdP sees it, whichever authenticator produced it
record IdpUser(string Subject, string Account, string Name, Func<string, bool> IsInGroup, Func<IReadOnlyList<GroupInfo>> ListGroups);

record MappingMatch(string Group, string Role, bool Matched);

record UserReport(string Subject, string Account, string Name, IReadOnlyList<GroupInfo> Groups, IReadOnlyList<MappingMatch> Mappings, string[] Roles);

static class IdpUsers
{
    public static string[] ResolveRoles(IdpUser user, IEnumerable<RoleMapping> mappings) =>
        mappings.Where(m => user.IsInGroup(m.Group)).Select(m => m.Role).Distinct().ToArray();

    public static UserReport Report(IdpUser user, IReadOnlyList<RoleMapping> mappings) =>
        new(user.Subject, user.Account, user.Name, user.ListGroups(),
            mappings.Select(m => new MappingMatch(m.Group, m.Role, user.IsInGroup(m.Group))).ToList(),
            ResolveRoles(user, mappings));

    public static IdpUser FromPersona(Persona p) => new(
        Subject: p.Sid,
        Account: p.Email,
        Name: p.Name,
        IsInGroup: group => p.Groups.Contains(group, StringComparer.OrdinalIgnoreCase),
        ListGroups: () => p.Groups.Select(g => new GroupInfo(g, null)).ToList());

    [SupportedOSPlatform("windows")]
    public static IdpUser FromWindows(WindowsIdentity identity)
    {
        var principal = new WindowsPrincipal(identity);

        // Accepts a group name (DOMAIN\Group) or a SID; a name that cannot be resolved counts as "not a member"
        bool IsInGroup(string group)
        {
            try
            {
                return group.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                    ? principal.IsInRole(new SecurityIdentifier(group))
                    : principal.IsInRole(group);
            }
            catch (SystemException)
            {
                return false;
            }
        }

        IReadOnlyList<GroupInfo> ListGroups() =>
            (identity.Groups ?? new IdentityReferenceCollection())
                .Select(sid => new GroupInfo(TryTranslate(sid), sid.Value))
                .OrderBy(g => g.Name ?? g.Sid)
                .ToList();

        return new IdpUser(identity.User?.Value ?? identity.Name, identity.Name, identity.Name, IsInGroup, ListGroups);
    }

    [SupportedOSPlatform("windows")]
    static string? TryTranslate(IdentityReference reference)
    {
        try
        {
            return reference.Translate(typeof(NTAccount)).Value;
        }
        catch (SystemException)
        {
            return null;
        }
    }
}

// Holds the group-to-role mappings, seeded from configuration and saved to a file when edited
partial class RoleMappingStore
{
    static readonly JsonSerializerOptions FileJson = new() { WriteIndented = true };

    readonly object gate = new();
    readonly string path;
    List<RoleMapping> mappings;

    public RoleMappingStore(IEnumerable<RoleMapping> configured, string path)
    {
        this.path = path;
        mappings = configured.ToList();

        // Edits made through the admin page live in the file and win over the configured defaults
        if (File.Exists(path))
        {
            mappings = JsonSerializer.Deserialize<List<RoleMapping>>(File.ReadAllText(path)) ?? mappings;
        }
    }

    public IReadOnlyList<RoleMapping> Snapshot()
    {
        lock (gate)
        {
            return mappings.ToList();
        }
    }

    // Returns an error message, or null on success
    public string? Add(RoleMapping mapping)
    {
        var error = Validate(mapping);
        if (error != null)
        {
            return error;
        }

        lock (gate)
        {
            if (mappings.Contains(mapping))
            {
                return "That mapping already exists.";
            }

            return Save(mappings.Append(mapping).ToList());
        }
    }

    public string? Remove(RoleMapping mapping)
    {
        lock (gate)
        {
            if (!mappings.Contains(mapping))
            {
                return "That mapping no longer exists.";
            }

            return Save(mappings.Where(m => m != mapping).ToList());
        }
    }

    string? Save(List<RoleMapping> updated)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            string temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(updated, FileJson));
            File.Move(temp, path, overwrite: true);
            mappings = updated;
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"Could not save the mappings file ({path}): {ex.Message}";
        }
    }

    static string? Validate(RoleMapping mapping)
    {
        if (string.IsNullOrWhiteSpace(mapping.Group) || mapping.Group.Length > 256 || mapping.Group.Any(char.IsControl))
        {
            return "Group is required (up to 256 characters).";
        }

        if (!RoleName().IsMatch(mapping.Role))
        {
            return "Role must be 1-64 characters: letters, digits, and _ . : -";
        }

        return null;
    }

    [GeneratedRegex("^[A-Za-z0-9_.:-]{1,64}$")]
    private static partial Regex RoleName();
}
