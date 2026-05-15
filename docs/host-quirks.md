# Host quirks

Per-host parser quirks tripwire has to work around. These are **time-bound** — they'll expire when upstream fixes the linked issues. Pull this doc back to the README if the list shrinks to one or zero entries.

## Codex CLI

Codex's PreToolUse handler is stricter than Claude Code's. Two specific rejections matter:

### `updatedInput` is rejected

Codex rejects `updatedInput` on PreToolUse responses outright — the `rewrite` outcome can't deliver a modified tool call back through Codex's hook surface.

- Tracking: [openai/codex#18491](https://github.com/openai/codex/issues/18491)
- Workaround: route `rewrite` outcomes through `deny + systemMessage` on Codex, advising the user (or agent) what to run instead. Lossier than rewriting in-place, but Codex is the host that's wrong here.

### `hookSpecificOutput.additionalContext` is rejected

Codex also drops `hookSpecificOutput.additionalContext` — the field Claude Code uses to inject warnings into the agent's next turn.

- Tracking: [openai/codex#19385](https://github.com/openai/codex/issues/19385)
- Workaround: emit warnings via `systemMessage` instead on Codex. Dispatcher normalizes this per-host via `isCodex(event)`.

## Tool-name normalization

Each host names the bash tool differently. The dispatcher maps:

| Host        | Tool name on PreToolUse                          |
| ----------- | ------------------------------------------------ |
| Claude Code | `Bash`                                           |
| Codex CLI   | `exec` / `apply_patch`                           |
| Pi          | `bash`                                           |
| Devin       | reads Claude Code settings, normalizes to `Bash` |

Rules accept either the canonical name (`Bash`) or the host-specific name; the per-host adapter does the translation before the rule fires.

## Installation path

Binaries should land in `~/.local/bin/tripwire-hook` and `~/.local/bin/tripwire`. Host configs reference the absolute path:

- Claude Code: `.claude/settings.json` → `hooks.PreToolUse[].command`
- Codex: `~/.codex/hooks.json`
- Pi: `npm:@hsingjui/pi-hooks` reads from `$HOME/.local/bin`
- Devin: auto-reads Claude Code settings

Reason: repo moves shouldn't break the hook wiring. A relative path in `~/dev/tripwire` would break the day Sean clones to a new machine or moves the repo.

## Companion: `betterleaks` for PostToolUse secret scrubbing

`post-secret-scrub` uses [betterleaks](https://github.com/zricethezav/betterleaks) (Zach Rice's gitleaks fork) for the PostToolUse path. Install via `brew install betterleaks`. The rule wraps it in a timeout and redacts hits before they escape the dispatcher.

## Glob expansion

`bash-scoped-rm` uses `shell-quote@^1.8` for tokenization. `ParseEntry`'s `op: 'glob'` needs explicit expansion — `shell-quote` returns it as a glob marker, not as expanded paths, so the rule has to walk it itself before path-matching.
