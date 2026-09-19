# Project context for Claude

A learning sandbox for OAuth 2.0 / OIDC in .NET 10. See [README.md](README.md) for the projects, endpoints, flows and diagrams. This file holds only what isn't obvious from the code.

## Ground rules

- **Add new projects rather than changing existing ones**, unless a change is necessary. (The user asked for this when MiniOidcIdp was added.)
- Everything is a mock for learning: in-memory state, plaintext passwords, plain HTTP. Don't present it as production-ready.

## Ports and run order

| Project | Port |
|---|---|
| MiniOidcServiceWeb or MiniOidcIdp (run one, not both) | 5121 |
| MiniProtectedApi | 5062 |
| MiniMcpServer | 5046 |
| MiniOidcClient (callback listener) | 8080 |

Start the identity provider first. MiniProtectedApi and MiniMcpServer read an `Auth` section from `appsettings.json` (`Authority`, `Audience`, `RoleClaimType`, and for MCP also `Resource` and `Scopes`). Override with environment variables such as `Auth__Authority`. Token `iss` follows the request address, so the authority must match how the IdP is reached.

## Habits that saved time

- **Leftover background servers hold ports.** Check with `ss -tlnp | grep -E ':(5121|5062|5046|8080)\b'` and free one with `fuser -k <port>/tcp`. Match the real process name (`MiniOidcService`), not `dotnet`.
- **Test on temporary ports** so a running instance isn't disturbed: `dotnet run --no-build --urls http://localhost:5400` with `Auth__Authority=...` set for the API and MCP server, plus `Auth__Audience=...` and `Auth__Resource=...` for the MCP server (its default port 5046 is often already taken by a running instance, which makes a new copy fail to start and hides that in test results).
- The OAuth interop test for the MCP server used the official `ModelContextProtocol` SDK client (`HttpClientTransport` with `ClientOAuthOptions`, dynamic registration, and a redirect delegate that submits the login form). It lived outside the repo and isn't saved here. Rebuild it if needed.
- Mermaid diagrams in the README can be parse-checked with the `mermaid` npm package and rendered with `@mermaid-js/mermaid-cli` using the system Chrome.

## Status and open items

- MiniOidcIdp: `Persona` mode is tested. `WindowsKestrel` and `WindowsIis` compile but have **never been run** (needs Windows).
- Claude Code authenticating to MiniMcpServer through its own OAuth flow has **not been tried**. Only the SDK client has.
- MiniOidcClient sends the `id_token` to MiniProtectedApi, which is a shortcut. The proper change is to send the `access_token` and give the API its own audience. Not done because it touches two existing projects.
- Ideas raised but not built: a `MiniMcpClient` project, a token-exchange endpoint for service-to-service calls, and a persistent signing key.

## Moving to another machine

Conversation history is not in the repo. See [docs/MOVING-CLAUDE-HISTORY.md](docs/MOVING-CLAUDE-HISTORY.md).
