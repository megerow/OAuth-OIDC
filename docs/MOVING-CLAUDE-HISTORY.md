# Moving this repo (and its Claude history) to another computer

Cloning or copying the repo does **not** bring your Claude Code conversations with it. Claude Code keeps history on the machine, outside the repository. This page says what lives where, and how to carry it across.

The paths and behavior below were checked on Linux against this repo and against the Claude Code docs (https://code.claude.com/docs/en/sessions.md). The copy procedure has not been tried on a second machine, so verify with the checklist at the end.

## What lives where

| Item | Location | Travels with the repo? |
|---|---|---|
| Project knowledge for Claude | [`CLAUDE.md`](../CLAUDE.md) and [`README.md`](../README.md) | Yes. Claude reads `CLAUDE.md` automatically on any machine. |
| Conversation transcripts | `~/.claude/projects/<encoded-path>/*.jsonl` | **No.** Copy them by hand. |
| Auto memory (notes Claude saved) | `~/.claude/projects/<encoded-path>/memory/` | **No.** Same folder as the transcripts. It is empty for this repo today. |
| Local-scope MCP servers (for example `mini-oidc`) | `~/.claude.json` | **No.** Re-add with `claude mcp add`. |
| Personal permissions and settings | `~/.claude/settings.json`, `.claude/settings.local.json` | **No.** |
| Your Claude login | Managed by Claude Code | **No.** Sign in again on the new machine. |

On Windows, `~` is `%USERPROFILE%` (for example `C:\Users\you`).

## The folder name depends on the repo's path

`<encoded-path>` is the absolute path of the folder you run Claude from, with **every character that is not a letter or digit replaced by `-`**. It is the same rule on Linux, macOS and Windows.

| Repo path | Folder name |
|---|---|
| `/home/mark/source/repos/OAuth+OIDC` | `-home-mark-source-repos-OAuth-OIDC` |
| `C:\Users\mark\source\repos\OAuth+OIDC` | `C--Users-mark-source-repos-OAuth-OIDC` |

To compute it for the current folder:

```bash
# bash (Linux, macOS, Git Bash)
echo -n "$PWD" | sed 's/[^A-Za-z0-9]/-/g'
```

```powershell
# PowerShell
$pwd.Path -replace '[^A-Za-z0-9]', '-'
```

If the repo sits at a different path on the new machine, the folder name changes too. Copy the old folder and rename it to the new name.

## Before you move: stop old transcripts being deleted

Claude Code deletes transcripts older than **30 days** by default (`cleanupPeriodDays`). Raise it on the old machine, in `~/.claude/settings.json`, before you need the history:

```json
{
  "cleanupPeriodDays": 365
}
```

## Steps

1. **Close Claude Code** (all VS Code windows and terminals using this repo) on the old machine so no transcript is mid-write.
2. **Find the folder** on the old machine:
   ```bash
   ls ~/.claude/projects/
   ```
   For this repo on Linux it is `-home-mark-source-repos-OAuth-OIDC`. Take the whole folder: transcripts, the per-session subfolders, and `memory/`.
3. **Package it** and move it by a private route (USB drive, `scp`, an encrypted archive):
   ```bash
   tar -czf claude-history.tar.gz -C ~/.claude/projects -- -home-mark-source-repos-OAuth-OIDC
   ```
4. **Clone or copy the repo** to the new machine and note its absolute path.
5. **Compute the new folder name** with the commands above, run from the repo folder on the new machine.
6. **Unpack under that name.** If the repo path is the same, unpack as is. If not, rename while unpacking:
   ```bash
   mkdir -p ~/.claude/projects/<new-encoded-path>
   tar -xzf claude-history.tar.gz -C ~/.claude/projects/<new-encoded-path> --strip-components=1
   ```
   On Windows, extract the archive and move the folder's contents into `%USERPROFILE%\.claude\projects\<new-encoded-path>\`.
7. **Install Claude Code, sign in, and re-add the MCP server** if you use it:
   ```bash
   claude mcp add --transport http mini-oidc http://localhost:5046/mcp
   ```

## Resuming a conversation

From the repo folder on the new machine, run `claude --resume` and pick the session. Alternatively resume from the file directly:

```bash
claude --resume ~/.claude/projects/<new-encoded-path>/<session-id>.jsonl
```

Per the docs, the desktop app, claude.ai/code and the VS Code extension each keep their own session lists. The transcript files for the VS Code extension do sit in the same folder here, but if a session doesn't appear in the picker, resume it by file path as shown above.

## Handle transcripts as sensitive

Transcripts hold everything Claude saw, including full tool output. For this repo that includes test tokens, Windows group names if you paste them in, and any secret that ever appeared in a command or file.

- **Do not commit** `~/.claude/projects/` to git, and don't put the archive in a shared folder.
- Move it over a channel you trust and delete the archive afterward.

## If you just want a readable copy

Use `/export` in a session for a plain-text copy of the conversation. It can be read anywhere, but it cannot be resumed.

## Checklist on the new machine

- [ ] `ls ~/.claude/projects/` shows a folder matching the encoded repo path
- [ ] `claude --resume` lists the old sessions (or resuming by file path works)
- [ ] Claude mentions the ports and run order from `CLAUDE.md` without being told
- [ ] `claude mcp list` shows `mini-oidc`, if you use it
