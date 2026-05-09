# tripwire

Opinionated hooks dispatcher for Claude Code, Codex CLI, Devin for Terminal, and Pi. One Bun binary, one rule set, four hosts.

## What it does

Sits in front of every `Bash` / `Read` / `Write` / `Edit` / `WebFetch` tool call across all four agents. On a tool call, tripwire parses the command (real shell-aware tokenizer, not regex), runs the rules, and returns one of four decisions:

- **allow** — silent passthrough (Bash calls additionally get rewritten through `rtk` for token-saver substitutions).
- **warn** — non-blocking advisory injected into the agent's next turn so it learns over time without hanging on a confirm.
- **ask** — Claude Code prompts the user before letting the call proceed.
- **deny** — block with a structured error message that names the safer alternative.

On `PostToolUse`, every Bash / Read / WebFetch output passes through `betterleaks` (Zach Rice's MIT gitleaks successor). If a secret is detected, the original output is withheld from the model and a `[REDACTED:rule-name]` version becomes the hook's block reason.

## Rules

| Rule                   | Action             | What it catches                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bash-deny`            | deny / ask         | Catastrophic deletes (`rm -rf /`, `~`, `$HOME`), fork bomb, `dd of=/dev/disk`, `mkfs`, `kill -9 -1`, `chmod -R 777`, `--no-verify`, `--no-gpg-sign`, `shutdown`/`reboot`, `launchctl bootstrap/load/unload`, `defaults write`, `csrutil`, `nvram`, `diskutil eraseDisk`, `tmutil delete`, `topgrade`, `mackup`, `rsync --delete`, `softwareupdate --install`, `pmset` write, `dscl -delete/-create`, `xattr -d com.apple.quarantine`, `spctl --master-disable`, `kextload`/`kmutil load`, `security delete-keychain`, `systemsetup -set*`, `scutil --set`. Asks on `sudo`, `osascript`, `brew install`, `mas install`, `security add-*-password`.       |
| `bash-git`             | deny / ask / allow | Smart git policy with `git -C` support. Read-only commands silent. **Conventional Commits enforced** on `git commit -m` (allowed types: `feat`/`fix`/`docs`/`style`/`refactor`/`perf`/`test`/`build`/`ci`/`chore`/`revert`). Blocks: `reset --hard`, `clean -fd`, `checkout .`, `checkout -- <path>`, `restore <path>`, `switch --discard-changes`, `commit --amend`, `rebase -i`, `filter-branch`, `gc --prune=now`, `update-ref`, `reflog expire`, `branch -D`, `branch -d` on `main`/`master`/`develop`/`production`/`release`, force push, `push --delete`, push to a protected branch, `tag -d`, `stash drop`/`clear`, `config --global/--system`. |
| `bash-scoped-rm`       | deny               | `rm` / `find -delete` outside ephemeral build / cache / state scopes (`dist`, `node_modules`, `.next`, etc.). Message tells the agent to use `trash` / `rip` instead.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `bash-redirect`        | deny               | `>`, `>>`, `tee`, `cp`, `mv` _into_ `.env`, `.dev.vars`, `~/.ssh/`, `*.pem`, `~/.aws/credentials`, `~/.netrc`, `/dev/sd*`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `bash-network-install` | deny / ask         | `curl`/`wget` piped to `bash`/`sh`/`zsh` denied. `cargo install`, `go install`, `gem install` ask.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `bash-tar-explosion`   | deny               | `tar -x -C /` / `~` / `$HOME`, `unzip -d /`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `bash-tool-policy`     | deny / warn        | **Toolchain enforcement.** Denies `npm`, `npx`, `pnpm`, `yarn`, `pip`, `python -m venv`, `uv venv` (use `uv sync`), `patch-package` — each with concrete redirection in the message. Warns on `find` (→ `fd`), `grep` (→ `rg`), `top` (→ `btop`), `du` (→ `dust`), `df` (→ `duf`), `ps` (→ `procs`), `cat` (→ `bat` / `rg` direct).                                                                                                                                                                                                                                                                                                                     |
| `imsg-deny`            | deny               | Raw `imsg` CLI. Use `send` instead.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `path-protect`         | deny               | Edit/Write on `.env`, `.ssh/`, `*.pem`, `~/.aws/credentials`, secret files.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `read-protect`         | deny               | Read on the same set — keeps secrets out of the model's context window.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `lazy-code`            | warn               | Diff-aware. Newly added lines in code files containing `TODO:` / `FIXME:` / `XXX:` / `HACK:` / `for now` / `not implemented` / `NotImplementedError` / `temp fix` / `fallback` / `placeholder` / `backwards compat` / `for later` / `to be implemented` / `not yet (implemented\|done)` / `stubbed`. Skips test/spec/fixture/mock/stories paths. Code files only — markdown, JSON, YAML, prose exempt.                                                                                                                                                                                                                                                  |
| `post-secret-scrub`    | deny (PostToolUse) | Pipes Bash/Read/WebFetch output through `betterleaks`. On hits, blocks the original output from reaching the model and surfaces a redacted version.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

## Bypass

For genuine edge cases:

- **Bash:** append `# tripwire-allow: <reason>` to the command.
- **Code files (any language):** put `tripwire-allow: <reason>` in any comment syntax (`//`, `#`, `--`, `/* */`, `<!-- -->`, etc.) on the offending line.

## Install

```bash
cd ~/dev/tripwire
bun install
bun run install:local      # builds, then copies to ~/.local/bin/
```

This produces two binaries on PATH (assuming `~/.local/bin` is in your PATH):

- `tripwire-hook` — the hook entry point invoked by all four agents.
- `tripwire` — the synthetic-event tester (see _CLI_ below).

## Wiring

### Claude Code

`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "/Users/sean/.local/bin/tripwire-hook" }] }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "/Users/sean/.local/bin/tripwire-hook" }] }
    ]
  }
}
```

### Codex CLI

Enable the feature flag in `~/.codex/config.toml`:

```toml
[features]
codex_hooks = true
```

Drop `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          { "type": "command", "command": "/Users/sean/.local/bin/tripwire-hook", "timeout": 10 }
        ]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [
          { "type": "command", "command": "/Users/sean/.local/bin/tripwire-hook", "timeout": 10 }
        ]
      }
    ]
  }
}
```

Verify with `codex features list | grep hooks` — should report `hooks  stable  true`.

### Devin for Terminal

**No setup needed.** Devin's `read_config_from.claude` defaults to true, so it picks up `~/.claude/settings.json` automatically. To opt out and use a Devin-only config, set `read_config_from.claude = false` in `~/.config/devin/config.json` and add hooks there directly.

### Pi (earendil-works)

Install the [pi-hooks](https://github.com/hsingjui/pi-hooks) plugin once, which adapts Claude-style hook config to Pi's extension API:

```bash
pi install npm:@hsingjui/pi-hooks
```

Then `~/.pi/agent/settings.json`:

```json
{
  "packages": ["npm:@hsingjui/pi-hooks", "..."],
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "/Users/sean/.local/bin/tripwire-hook" }] }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "/Users/sean/.local/bin/tripwire-hook" }] }
    ]
  }
}
```

`/reload` inside Pi to pick it up.

## CLI

`tripwire test` pipes a synthetic event through the hook so you can see what would happen without going through an agent.

```bash
tripwire test 'rm -rf /etc'
tripwire test 'git commit -m "wip"'
tripwire test 'npm install foo'
tripwire test --tool=Read --path=.env
tripwire test --tool=Write --path=foo.ts --content='TODO: finish'
tripwire test --post --tool=Bash --stdout='ghp_REAL_TOKEN_HERE'
```

## Cross-host tool-name normalization

The dispatcher canonicalizes tool names from each host before routing:

| Host           | Bash                                | File edits                                  | Read   |
| -------------- | ----------------------------------- | ------------------------------------------- | ------ |
| Claude Code    | `Bash`                              | `Edit` / `Write` / `MultiEdit`              | `Read` |
| Codex          | `Bash` (also `shell`/`run_command`) | `apply_patch` (with `Edit`/`Write` aliases) | `Read` |
| Devin          | `exec`                              | `Write` / `Edit`                            | `Read` |
| Pi (lowercase) | `bash`                              | `write` / `edit`                            | `read` |

All map to a single internal vocabulary, so rule code never branches on host.

## Design rules

- **A buggy or slow rule must never block the agent.** Every rule runs under a 250ms timeout (5s for the betterleaks PostToolUse step). Defects and timeouts collapse to `allow`, logged to `~/.claude/tripwire.log`.
- **Block messages address the agent in second person and name the concrete alternative.** No vague "denied for safety" output.
- **Codex compatibility:** Codex rejects `hookSpecificOutput.additionalContext` on `PreToolUse` (openai/codex#19385). Detected via Codex's `turn_id` field; warns degrade to top-level `systemMessage`, which both hosts support.
- **One bypass token, comment-syntax-agnostic.** `tripwire-allow: <reason>` works in `//`, `#`, `--`, `/* */`, `<!-- -->`, `;`, `%`.

## Stack

- **Bun** runtime, minified + bytecode-cached for ~50ms cold start.
- **Effect v4** for per-rule timeouts and exit isolation.
- **shell-quote** for shell tokenization (mature, 12 years, 1.8M weekly DLs).
- **betterleaks** subprocess for secret scanning (MIT, by the original gitleaks author).
- **rtk** subprocess for command-rewrite passthrough on allowed Bash calls.
- Strict oxlint + tsc — no warnings.
- 114 tests, all green.

## Layout

```
src/
  dispatch.ts                # entry — reads stdin, routes, writes JSON decision
  cli.ts                     # tripwire test ... synthetic-event tester
  lib/
    bash.ts                  # shell-quote wrapper, segment + safe-path helpers
    decision.ts              # Decision type, merge logic
    diff.ts                  # added-lines diff for lazy-code
    event.ts                 # HookEvent schema + tool-input type guards
    log.ts                   # ~/.claude/tripwire.log (errors only)
    rtk.ts                   # rtk hook claude subprocess wrapper
    secrets.ts               # betterleaks subprocess wrapper
  rules/
    bash-deny.ts             bash-git.ts             bash-network-install.ts
    bash-redirect.ts         bash-scoped-rm.ts       bash-tar-explosion.ts
    bash-tool-policy.ts      imsg-deny.ts            lazy-code.ts
    path-protect.ts          post-secret-scrub.ts    read-protect.ts
test/
  dispatch.test.ts           # 114 tests across all rules
```
