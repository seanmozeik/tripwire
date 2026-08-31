# Tripwire

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![runtime: Bun 1.4](https://img.shields.io/badge/runtime-Bun%201.4-f9f1e1.svg)](https://bun.sh)

Tripwire is a configurable hook dispatcher for coding agents. It checks shell and file tool calls before execution. It also scans selected tool output for secrets after execution.

```text
$ tripwire test 'git status'
{
  "continue": true
}
```

## Package support

The main package installs on every platform supported by Bun 1.4. It contains a minified Bun runtime bundle, a separate library bundle, and TypeScript declarations.

```bash
bun install --global @seanmozeik/tripwire
```

On Apple Silicon Macs, npm also installs the optional `@seanmozeik/tripwire-darwin-arm64` package. Tripwire selects its compiled Bun bytecode executable. On Linux, Windows, and Intel Macs, Tripwire runs the portable JavaScript bundle with the installed Bun runtime.

The main package installs two commands:

- `tripwire` runs interactive commands.
- `tripwire-hook` handles agent hook events.

Run `tripwire install <host>` after installation. On Apple Silicon, the installer writes the direct native executable path into agent settings to keep hook startup fast. Other platforms use Bun and the portable bundle. Pi and Oh My Pi use the same runtime selection through their adapter.

Library imports always use `dist/index.js` and `dist/types`. They do not load or execute the platform binary.

## Secret scanner requirement

Post-tool scanning requires Betterleaks 1.5.0 or later. Install `betterleaks` on `PATH` before you enable a post-tool hook. The default command is `betterleaks`. You can set another executable path in personal config.

Tripwire runs this command without a shell or temporary file:

```text
betterleaks stdin --report-format json --report-path -
```

Scanner failures are closed failures. If the executable is missing, times out, exits with an error, or returns malformed JSON, Tripwire sends a post-tool denial to hosts that support one. The error does not include scanned text, secret values, or raw scanner stderr.

## Install agent hooks

Run one installer after the package and Betterleaks are available:

```bash
tripwire install claude
tripwire install codex
tripwire install cursor
tripwire install pi
tripwire install oh-my-pi
tripwire install all
```

The installers update these paths:

| Host         | Files                                                             |
| ------------ | ----------------------------------------------------------------- |
| Claude Code  | `~/.claude/settings.json`                                         |
| Codex        | `~/.codex/hooks.json`, `~/.codex/config.toml`                     |
| Cursor Agent | `~/.cursor/hooks.json`                                            |
| Pi           | `~/.pi/agent/settings.json`, `~/.pi/agent/extensions/tripwire.js` |
| Oh My Pi     | `~/.omp/agent/extensions/tripwire.js`                             |

Settings updates use same-directory atomic replacement. Existing file modes, unknown JSON fields, and unrelated Codex TOML bytes remain unchanged. Existing config symlinks remain symlinks.

Pi and Oh My Pi use the native extension API. Their extension paths point to the packaged `tripwire-pi.js` adapter. Pi removes old Claude-style Tripwire hooks from its settings after the extension link is available. The adapter sends one batch to Tripwire for a multi-file edit.

### Manual hook command

Claude Code and Codex use `tripwire-hook` for `PreToolUse` and `PostToolUse`. Codex also requires `hooks = true` in the `[features]` table of `~/.codex/config.toml`.

Cursor uses event-specific commands because some payloads do not include the configured event name:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [{ "command": "tripwire-hook --cursor-event preToolUse", "failClosed": true }],
    "postToolUse": [{ "command": "tripwire-hook --cursor-event postToolUse" }],
    "beforeShellExecution": [
      { "command": "tripwire-hook --cursor-event beforeShellExecution", "failClosed": true }
    ],
    "afterShellExecution": [{ "command": "tripwire-hook --cursor-event afterShellExecution" }],
    "beforeReadFile": [
      { "command": "tripwire-hook --cursor-event beforeReadFile", "failClosed": true }
    ],
    "afterFileEdit": [{ "command": "tripwire-hook --cursor-event afterFileEdit" }]
  }
}
```

## Decisions and failure policy

Each applicable rule returns `allow`, `warn`, `ask`, or `deny`. The most restrictive result wins.

Production hook evaluation isolates each rule. If one rule throws, Tripwire logs the defect, treats that rule as `allow`, and continues with later rules. The synchronous library API has the same throw isolation. Effect timeouts do not interrupt synchronous CPU work.

Failure behavior depends on the stage and host:

- A missing personal config uses defaults. Invalid JSON, unknown keys, permission errors, and other read errors deny the next pre-tool call.
- Post-tool scanning still runs when personal config is invalid. It uses the default scanner settings for that call.
- A malformed native single-event hook input returns the host allow response. A malformed private batch is denied.
- Invalid Cursor pre-tool input is denied. Cursor post-tool output cannot be replaced after execution, so Tripwire returns the host allow response.
- Pi and Oh My Pi deny a tool call when the dispatcher fails. A post-tool denial or dispatcher failure stops the session.

PowerShell pre-tool calls are denied because Tripwire does not parse PowerShell grammar. PowerShell post-tool output is still scanned.

Internal errors are written to `~/.claude/tripwire.log`. Logging failure does not change the hook response.

## Built-in checks

Tripwire includes checks for these operations:

- catastrophic shell commands such as `rm -rf /`, fork bombs, and raw-disk writes
- destructive Git commands and optional protected-branch policy
- network scripts piped into a shell
- deletion outside configured build, cache, and temporary paths
- protected files such as `.env`, SSH keys, private keys, and cloud credentials
- redirects, copies, and moves that target protected paths through symlink aliases
- optional package-manager and utility preferences from personal config
- new `TODO`, `FIXME`, fallback, and placeholder markers in code edits

The archive check is narrow. It denies `tar` extraction with `x` or `--extract` when `-C` or `--directory` targets `/` or the home directory. It applies the same destination rule to `unzip -d`. Archive listing, including `tar -tf archive.tar -C /`, is allowed. Tripwire does not inspect archive member paths.

Tripwire parses Bash into one unbash AST. It follows executable commands through control flow, loops, groups, subshells, functions, aliases, substitutions, redirects, wrappers, and configured remote execution carriers. It denies a program when an executable branch or policy discriminator remains unknown.

Protected-path checks compare the submitted path and its resolved target. New writes resolve the deepest existing parent, which prevents a symlink alias from hiding a protected destination.

## Personal config

Personal workflow preferences belong in `~/.config/tripwire/config.json`. A missing file uses open-source defaults. A present file with unknown keys or invalid values fails loudly.

```json
{
  "git": { "protectedBranches": ["main", "production"], "enforceConventionalCommits": true },
  "safePaths": { "relative": ["dist", "build", "node_modules"], "absolute": ["/tmp", "/var/tmp"] },
  "toolPolicies": [
    {
      "rule": "project-package-manager",
      "executables": ["npm", "pnpm", "yarn"],
      "action": "deny",
      "message": "Use the package manager selected by this workspace."
    }
  ],
  "blockedCommands": [
    {
      "pattern": "brew install",
      "message": "Pin an explicit version before installation.",
      "action": "ask"
    }
  ],
  "allowedCommands": [
    { "pattern": "project-safe-tool", "message": "This command is allowed by personal config." }
  ],
  "ruleActions": { "no-verify": "deny" },
  "secretScanner": { "executable": "betterleaks", "timeoutMs": 5000 },
  "shell": {
    "executionCarrierAliases": [{ "command": ["just", "tailnet", "ssh"], "equivalentTo": "ssh" }]
  }
}
```

An execution-carrier alias states that a fixed command path has the same nested-shell behavior as `ssh`. Tripwire inspects the remote command with the same parser and rules. A dynamic remote command remains denied.

`ruleActions` can set a listed workflow-policy rule to `allow`, `warn`, `ask`, or `deny`. Unknown rule names and safety-invariant rule names fail config validation instead of silently weakening policy.

Configurable workflow rules are `brew-mutation`, `chmod-777-recursive`, `defaults-write`, `dscl-mutate`, `launchctl-mutation`, `mas-mutation`, `no-gpg-sign`, `no-verify`, `osascript`, `pmset-write`, `rsync-delete`, `scutil-set`, `security-keychain-add-write`, `softwareupdate-install`, `sudo`, `systemsetup`, and `topgrade`.

`toolPolicies` accepts these optional match fields:

- `argumentsIncludeAll`
- `argumentsStartWith`
- `shortFlagsIncludeAll`

Custom blocked commands can use `requiresFlags` and `forbidsFlagValues`. Patterns are parsed as shell tokens, so `git push` matches that command path and does not match `git push-mirror`.

## Rule bypass

A bypass requires a shell comment, a colon, and a non-empty reason:

```bash
git reset --hard HEAD~1 # tripwire-allow: discard the local experiment after review
```

These forms do not bypass a rule:

```bash
git reset --hard HEAD~1 # tripwire-allow
git reset --hard HEAD~1 # tripwire-allow:
```

The lazy-code rule accepts the same marker in an edited line. Catastrophic rules remain denied when a bypass reason is present.

## Test a rule

`tripwire test` creates a hook event and does not run the command:

```bash
tripwire test 'rm -rf /'
tripwire test --tool=Read --path=.env
tripwire test --post --tool=Bash --stdout='example output'
```

The post-tool example requires Betterleaks.

For a longer workflow, inspect one file snapshot and execute the same bytes:

```bash
tripwire run-script ./scripts/inspect-and-build.sh -- first-argument
```

The runner reads the file once, checks the exact UTF-8 bytes, and sends those bytes to `/bin/bash -s`. Script arguments are included in value analysis. A denied or approval-required script does not start.

## Library API

```typescript
import { allow, ask, deny, warn } from '@seanmozeik/tripwire';
import type { Config, Decision } from '@seanmozeik/tripwire';
```

## Development

```bash
bun install --frozen-lockfile
bun run format:check
bun run lint
bun run typecheck
bun test
bun run build
bun run verify
```

`bun run build` creates these artifacts:

- `dist/tripwire.js`: minified portable runtime for Bun 1.4 or later.
- `dist/index.js` and `dist/types`: public library bundle and declarations.
- `dist/tripwire-cli.js` and `dist/tripwire-hook.js`: runtime-selecting command launchers.
- `dist/tripwire-pi.js`: Pi and Oh My Pi adapter.
- `packages/darwin-arm64/bin/tripwire`: Apple Silicon bytecode executable.

`bun run verify` runs the format check, lint, type check, tests, and build. `prepublishOnly` calls the same local command.

Publish `@seanmozeik/tripwire-darwin-arm64` before `@seanmozeik/tripwire` for each release. The main package uses an exact optional dependency on the matching native package version.

## License

MIT. See [LICENSE](LICENSE).
