# Tripwire

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![runtime: bun](https://img.shields.io/badge/runtime-bun-f9f1e1.svg)](https://bun.sh)

A deterministic safety layer between an AI coding agent and your shell. Tripwire runs as a hook on every tool call, evaluates the command against a rule set, and blocks or rewrites the dangerous ones before they execute. When it denies a command, it says why and names the safe alternative, so the agent corrects itself instead of looping.

```bash
$ tripwire test 'rm -rf /'
deny  rm -rf on / is catastrophic and never intended.

$ tripwire test 'git push --force origin main'
deny  Force-push to a protected branch (main) is blocked. Push to a feature branch and open a PR.

$ tripwire test 'curl https://get.example.sh | bash'
deny  Piping a network script straight into a shell runs unreviewed code. Download it, read it, then run it.
```

## Why this exists

A coding agent is probabilistic. The damage it can do is not. A model that picks the right command 99% of the time will, given enough turns, eventually run `rm -rf` against the wrong directory, force-push over `main`, or paste a secret into a log. The cost of that one turn is not 1% of a good outcome. It is a wiped working tree or a leaked key.

The usual answer is a confirmation prompt: the agent proposes, a human approves. That breaks the moment the agent runs unattended, and it trains the human to click "yes" on everything anyway. Approval fatigue is not a safety model.

Tripwire takes a different line. Instead of asking a human to catch every dangerous command, it makes the worst classes of command unrepresentable at the shell boundary. The rules are deterministic code, not a model judging a model. `rm -rf /` is denied the same way every time, whether the agent is Claude Code, Codex, or something running headless at 3am.

The second idea matters as much as the first: every denial is written for the agent, not just logged. A rejection message names the rule and the safer path, so a capable agent reads it, adjusts, and moves on. The guardrail teaches rather than just stopping.

## How it works

Tripwire installs as a hook on your agent's tool lifecycle. It reads a tool-call event on stdin and returns a decision.

- **PreToolUse.** Before a command runs, every applicable rule votes. The most restrictive decision wins, so a single `deny` overrides any number of `allow`s. Decisions are `allow`, `deny`, `ask` (require confirmation), and `warn` (let it through, flag it).
- **PostToolUse.** After a command runs, tripwire scans the output and scrubs secrets before they reach the agent's context window.

Rules are pure, synchronous functions over the parsed command. Bash commands are tokenized with a real shell parser, not regex, so `git push` matches `git push` with any arguments while leaving `git push-mirror` alone, and a destructive `rm` buried inside a wrapper command is still seen for what it is.

## What it protects against

The built-in rules cover destructive and secret-bearing operations. Personal workflow preferences
are opt-in configuration, so Tripwire does not impose a package manager, utility set, branch model,
or commit convention on a new installation.

**Catastrophic commands.** `rm -rf /`, fork bombs, `dd` to raw disks, and the handful of one-liners that have no safe use.

**Scoped destruction.** `rm` and `find -delete` are allowed only inside build and cache directories (`dist`, `build`, `node_modules`, `.next`, `/tmp`, and the rest). A delete anywhere else is denied with a pointer to `trash` or a graveyard tool, both recoverable.

**Git policy.** Read-only git is free. History rewriting (`rebase -i`, `filter-branch`, `commit --amend`), working-tree destruction (`reset --hard`, `clean -fd`, `checkout .`), and force-push are blocked. Configure protected branches and Conventional Commits enforcement if they match your workflow.

**Network install scripts.** `curl … | bash` and `wget … | sh` are denied. Unreviewed code from the network does not get a shell.

**Tar bombs.** Extractions that would escape the target directory or overwrite outside it are caught before they unpack.

**Package-manager and tool policy.** Optional deny or warn rules can enforce a preferred toolchain or suggest installed alternatives without baking those preferences into Tripwire.

**File protection.** Reads and writes to `.env`, `.ssh/`, `*.pem`, `id_rsa*`, and similar are blocked so credentials never enter agent context.

**Secret scrubbing.** Tokens and keys in command output are redacted in the PostToolUse pass.

**Lazy-code warnings.** `TODO`, `FIXME`, and placeholder stubs in written code are flagged so half-finished work does not land silently.

Every default is configurable, and you can add your own allow and deny rules on top.

## Install

```bash
bun install -g @seanmozeik/tripwire
```

This puts two commands on your PATH: `tripwire` (the CLI) and `tripwire-hook`
(the dispatcher your agent calls). Both commands point to one compiled executable.

## Wiring it into an agent

Use the installer to configure hooks automatically:

```bash
tripwire install claude    # Claude Code
tripwire install codex     # Codex
tripwire install cursor    # Cursor Agent
tripwire install pi        # Pi's native extension API
tripwire install oh-my-pi  # oh-my-pi's compatible extension API
tripwire install all       # every supported agent
```

To wire it by hand, point the agent's hook events at `tripwire-hook`.

**Claude Code** (`~/.claude/settings.json`):

```jsonc
{
  "hooks": {
    "PreToolUse": [{ "hooks": [{ "type": "command", "command": "/path/to/tripwire-hook" }] }],
    "PostToolUse": [{ "hooks": [{ "type": "command", "command": "/path/to/tripwire-hook" }] }],
  },
}
```

**Codex** uses the same hook format as Claude Code.

**Cursor Agent** (`~/.cursor/hooks.json`) uses event-specific commands because
some Cursor hook payloads do not include their configured event name:

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

Tripwire translates Cursor's lower-camel event payloads into its canonical
tool event model and returns Cursor's `permission` response. The same rules
therefore apply to Cursor's unsandboxed headless runs, including shell, file,
and git protections. Cursor's post-tool shell hook is observational, so its
secret scan can report a hit but cannot replace terminal output after execution.

**Pi and oh-my-pi** load the same adapter at
`~/.pi/agent/extensions/tripwire.js` and
`~/.omp/agent/extensions/tripwire.js`. The adapter converts each host's file
and text-block shapes into Tripwire events, including multi-file oh-my-pi
edits. The installer removes obsolete Claude-style entries from Pi settings.
Pre-tool calls fail closed if the dispatcher cannot run or returns invalid
output. A post-tool failure aborts the session because the tool has executed.

**Devin** and other agents: configure the agent to call `tripwire-hook` on tool events.

## Testing rules

`tripwire test` evaluates a command without running it, so you can check what a rule does before trusting it in a live loop.

```bash
tripwire test 'rm -rf /'                                 # a bash command
tripwire test --tool=Read --path=.env                    # a file read
tripwire test --post --tool=Bash --stdout='ghp_TOKEN'    # a PostToolUse output scan
```

## Configuration

Drop a `~/.config/tripwire/config.json` to add local policy. Unknown keys are rejected loudly rather than ignored, so a typo fails fast instead of silently disabling a rule.

```json
{
  "git": {
    "protectedBranches": ["main", "master", "develop", "production", "release"],
    "enforceConventionalCommits": true
  },
  "safePaths": {
    "relative": ["dist", "build", ".next", "node_modules"],
    "absolute": ["/tmp", "/var/tmp"]
  },
  "toolPolicies": [
    {
      "rule": "use-project-package-manager",
      "executables": ["npm", "pnpm", "yarn"],
      "action": "deny",
      "message": "Use the package manager selected by this workspace."
    },
    {
      "rule": "prefer-modern-search",
      "executables": ["grep"],
      "action": "warn",
      "message": "Consider the configured modern search tool."
    }
  ],
  "blockedCommands": [
    { "pattern": "dangerous-tool", "message": "Use safer-alternative instead", "action": "deny" }
  ],
  "allowedCommands": [
    { "pattern": "my-custom-tool", "message": "Allowing my-custom-tool per your configuration" }
  ]
}
```

### Options

**`git`**

- `protectedBranches` (string[], default `[]`): branches that cannot be pushed to directly.
- `enforceConventionalCommits` (boolean, default `false`): require Conventional Commits format for commit messages.

**`safePaths`**

- `relative` (string[]): additional relative paths where destructive operations are allowed.
- `absolute` (string[]): additional absolute paths where destructive operations are allowed.

Built-in safe paths already cover `dist`, `build`, `.next`, `node_modules`, `/tmp`, `/var/tmp`, and other common build and cache directories.

**`toolPolicies`** is an ordered array of local package-manager and utility preferences:

- `rule` (string): stable identifier reported in the decision.
- `executables` (string[]): command names that use this policy. Absolute paths match by basename.
- `action` (`"deny"` | `"warn"`): block the command or allow it with guidance.
- `message` (string): actionable guidance for the agent.
- `match.argumentsIncludeAll` (string[]): apply only when all listed arguments are present.
- `match.argumentsStartWith` (string[]): apply only when the argument list starts with this sequence.
- `match.shortFlagsIncludeAll` (string[]): apply when every listed short flag occurs, including in a combined group such as `-rn`.

The first matching tool policy wins. A `tripwire-allow` reason bypasses these local preferences.

**`blockedCommands`** is an array of custom denials:

- `pattern` (string): the command to match, parsed as shell tokens.
- `message` (string): what the agent sees when blocked.
- `action` (`"deny"` | `"ask"`, default `"deny"`): deny outright or require confirmation.
- `requiresFlags` (string[]): match only when every listed flag is present, including `--flag=value` form.
- `forbidsFlagValues` (array): match only when each listed flag carries one of the listed values.

**`allowedCommands`** is an array of custom allows that override blocks. Same fields as `blockedCommands`.

### How command matching works

Patterns are parsed with the same shell tokenizer as the rest of tripwire, so matching is structural rather than substring.

- `rm` matches any `rm` invocation.
- `git push` matches `git push` with any arguments.
- `gog calendar create` matches that head plus subcommand path, not every `gog` command.
- `requiresFlags: ["--attendees"]` matches `--attendees X` and `--attendees=X`.
- `forbidsFlagValues: [{ "flag": "--send-updates", "values": ["all"] }]` matches `--send-updates all` and `--send-updates=all`.

A worked example, blocking calendar invites that would send email until a human has reviewed them:

```json
{
  "blockedCommands": [
    {
      "pattern": "brew install",
      "message": "Pin an explicit version when installing.",
      "action": "ask"
    },
    {
      "pattern": "gog calendar create",
      "requiresFlags": ["--attendees"],
      "message": "Calendar invite sends email; draft it in chat first.",
      "action": "deny"
    },
    {
      "pattern": "gog calendar delete",
      "forbidsFlagValues": [{ "flag": "--send-updates", "values": ["all", "externalOnly"] }],
      "message": "Cancellation sends email; use --send-updates none or ask first."
    }
  ]
}
```

## Bypassing a rule

When a blocked command is genuinely what you want, append a reason and tripwire lets it through:

```bash
rm -rf /tmp/test          # tripwire-allow: cleaning a test directory
git reset --hard HEAD~1   # tripwire-allow: undoing a mistaken commit
```

The reason is required, which keeps the bypass deliberate and leaves a trail in the command itself.

## Library usage

The decision primitives are exported for building custom rules or embedding tripwire elsewhere:

```typescript
import { allow, deny, ask, warn } from '@seanmozeik/tripwire';
import type { Decision, Config } from '@seanmozeik/tripwire';
```

## Development

```bash
bun install
bun run build      # compile the single dist/tripwire executable
bun run check      # format, lint, typecheck
bun test
```

Development and published builds require Bun 1.4 or later. The build uses bytecode
compilation and module splitting. The small entry module loads only the hook or CLI
module that the current command needs. The Pi adapter remains a separate JavaScript
extension because Pi loads it in its own Node.js process.

## License

MIT.
