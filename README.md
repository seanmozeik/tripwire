# `@seanmozeik/tripwire`

Opinionated hooks dispatcher for AI coding agents (Claude Code, Codex, Devin, etc.) with configurable safety rules. Blocks or rewrites dangerous commands with actionable error messages.

## Installation

```bash
bun install @seanmozeik/tripwire
```

## CLI

```bash
tripwire test '<command>'                 # Test a command
tripwire test --tool=Read --path=.env     # Test Read tool
tripwire test --post --tool=Bash --stdout='ghp_TOKEN'  # Test PostToolUse

tripwire install claude                   # Install hooks for Claude Code
tripwire install codex                    # Install hooks for Codex
tripwire install pi                       # Install hooks for pi-guardrails
tripwire install all                      # Install hooks for all agents
```

## Hook Configuration

Configure your AI agent to call `tripwire-hook` for hook events. You can do this manually, or use the `tripwire install` command to automatically configure hooks for supported agents:

### Claude Code

`~/.claude/settings.json`:

```jsonc
{
  "hooks": {
    "PreToolUse": [{ "hooks": [{ "type": "command", "command": "/path/to/tripwire-hook" }] }],
    "PostToolUse": [{ "hooks": [{ "type": "command", "command": "/path/to/tripwire-hook" }] }],
  },
}
```

### Codex

Same as Claude Code — Codex uses the same hook format.

### Devin

Configure in your Devin settings to call `tripwire-hook` for tool events.

## Configuration

Create `~/.config/tripwire/config.json` to customize behavior:

```json
{
  "rtk": { "enabled": true, "path": "/opt/homebrew/bin/rtk" },
  "git": {
    "protectedBranches": ["main", "master", "develop", "production", "release"],
    "enforceConventionalCommits": true
  },
  "safePaths": {
    "relative": ["dist", "build", ".next", "node_modules"],
    "absolute": ["/tmp", "/var/tmp"]
  },
  "blockedCommands": [
    { "pattern": "dangerous-tool", "message": "Use safer-alternative instead", "action": "deny" }
  ],
  "allowedCommands": [
    {
      "pattern": "my-custom-tool",
      "message": "Allowing my-custom-tool per your configuration",
      "action": "allow"
    }
  ]
}
```

### Configuration Options

#### `rtk`

- `enabled` (boolean, default: `false`) — Enable rtk token-saver integration
- `path` (string, optional) — Path to rtk binary. If not specified, searches common locations.

#### `git`

- `protectedBranches` (string[], default: `["main", "master", "develop", "production", "release"]`) — Branches that require PR for push
- `enforceConventionalCommits` (boolean, default: `true`) — Enforce Conventional Commits format for commit messages

#### `safePaths`

- `relative` (string[], optional) — Additional relative paths considered safe for destructive operations
- `absolute` (string[], optional) — Additional absolute paths considered safe for destructive operations

Default safe paths include: `dist`, `build`, `.next`, `node_modules`, `/tmp`, `/var/tmp`, and other common build/cache directories.

#### `blockedCommands`

Array of custom command blocks:

- `pattern` (string) — Command pattern to block (uses shell parsing for matching)
- `message` (string) — Error message shown when blocked
- `action` (`"deny"` | `"ask"`, default: `"deny"`) — Whether to deny or ask for confirmation

#### `allowedCommands`

Array of custom command allows (overrides blocks):

- `pattern` (string) — Command pattern to allow
- `message` (string) — Message shown when allowed
- `action` (string, default: `"allow"`) — Always `"allow"` for this context

### Shell-Based Command Matching

Command patterns in `blockedCommands` and `allowedCommands` use the same shell parsing as the rest of tripwire. This means:

- `rm` matches any `rm` command
- `git push` matches `git push` with any arguments
- Patterns are parsed using shell-quote for accurate matching
- More sophisticated than simple regex

Example:

```json
{
  "blockedCommands": [
    {
      "pattern": "brew install",
      "message": "Use brew install with explicit version pinning",
      "action": "ask"
    }
  ]
}
```

## Default Behavior

Tripwire comes with opinionated but reasonable defaults:

### Bash Safety

- Blocks catastrophic commands: `rm -rf /`, fork bombs, `dd` to disks
- Blocks macOS system mutations: `defaults write`, `launchctl`, `diskutil erase`
- Blocks cloud destructive operations: `gh repo delete`, `flyctl destroy`
- Scopes `rm` and `find -delete` to safe paths (build outputs, cache directories)
- Blocks network install scripts: `curl | bash`, `wget | sh`
- Enforces package manager policy: Bun-only, no npm/pnpm/yarn/pip

### Git Policy

- Read-only operations allowed: `status`, `log`, `diff`, `fetch`, etc.
- Blocks working-tree destruction: `reset --hard`, `clean -fd`, `checkout .`
- Blocks history rewriting: `rebase -i`, `filter-branch`, `commit --amend`
- Blocks force push and protected branch pushes
- Enforces Conventional Commits format (configurable)
- Requires `-m "message"` for commits (no editor mode)
- Asks for confirmation on merge/rebase/cherry-pick

### File Protection

- Blocks reads/writes to `.env`, `.ssh/`, `*.pem`, `id_rsa*`, etc.
- Warns on TODO/FIXME/placeholder in code (configurable)
- Scrubs secrets from tool output

## Bypass

Add `# tripwire-allow: <reason>` to bypass any rule:

```bash
rm -rf /tmp/test  # tripwire-allow: cleaning test directory
git reset --hard HEAD~1  # tripwire-allow: undoing mistaken commit
```

## Library Usage

```typescript
import { allow, deny, ask, warn } from '@seanmozeik/tripwire';
import type { Decision, Config } from '@seanmozeik/tripwire';
```

## Development

```bash
bun install
bun run build      # Build dist/tripwire.js and dist/tripwire-cli.js
bun run check      # Format + lint + typecheck
bun test           # Run tests
```

## License

MIT
