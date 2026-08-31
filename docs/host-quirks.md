# Host behavior

Tripwire normalizes host payloads before it runs rules. Each host still has a different response format and failure policy.

## Claude Code

Claude Code uses canonical `PreToolUse` and `PostToolUse` events. Warnings use `hookSpecificOutput.additionalContext`. A deny or ask decision uses `hookSpecificOutput.permissionDecision`.

The installer updates `~/.claude/settings.json` and registers `tripwire-hook` for both event phases.

## Codex

Codex events include `turn_id`. Tripwire uses that field to select Codex response formatting.

Codex warning responses use `systemMessage`. Tripwire does not send `hookSpecificOutput.additionalContext` to Codex. Pre-tool deny and ask decisions use the canonical permission fields.

The installer validates both files before it writes either one:

- `~/.codex/hooks.json`
- `~/.codex/config.toml`

It publishes `hooks.json` first, then sets `hooks = true` in the `[features]` TOML table. The first file is inactive until the feature is enabled. A retry repairs a first-file-only update.

## Cursor Agent

Cursor uses lower-camel event names and several event-specific payload shapes. Installed commands include `--cursor-event <name>` because some payloads omit that name.

Cursor pre-tool events return `permission: allow` or `permission: deny`. An `ask` result becomes a deny because an unattended Cursor hook cannot ask a person.

Cursor post-tool hooks are observational. The tool has already returned output, so Tripwire cannot replace it through the Cursor response. Post-tool failures return the host allow shape.

The installer updates `~/.cursor/hooks.json`.

## Pi and Oh My Pi

Pi and Oh My Pi load `tripwire-pi.js` through their native extension API:

- Pi: `~/.pi/agent/extensions/tripwire.js`
- Oh My Pi: `~/.omp/agent/extensions/tripwire.js`

The adapter resolves the native `tripwire` file beside the built extension. A multi-file edit becomes one canonical batch and one child process.

Pre-tool dispatcher failure, invalid JSON, and deny or ask results block the tool call. A post-tool denial or dispatcher failure reports an error and aborts the session. The adapter has a 60-second child-process timeout.

The Pi installer also reads `~/.pi/agent/settings.json`. It makes the extension link available before it removes old Claude-style Tripwire hook entries. Oh My Pi has no settings rewrite.

## Tool names

The dispatcher maps host tool names to its canonical names:

| Input names                                     | Canonical name |
| ----------------------------------------------- | -------------- |
| `bash`, `exec`, `shell`, `run_command`          | `Bash`         |
| `read`, `read_file`                             | `Read`         |
| `write`, `write_file`                           | `Write`        |
| `edit`, `edit_file`, `multiedit`, `apply_patch` | `Edit`         |
| `webfetch`, `web_fetch`, `fetch`                | `WebFetch`     |
| `powershell`                                    | `PowerShell`   |

PowerShell pre-tool calls are denied because Tripwire has no PowerShell parser. PowerShell post-tool output is normalized for secret scanning.

## Package paths

The main registry package installs `tripwire` and `tripwire-hook` as Bun launchers. It also provides the public library bundle at `dist/index.js` and declarations under `dist/types`.

On Darwin arm64, the launchers select the optional `@seanmozeik/tripwire-darwin-arm64` executable. Host installers write this direct executable path into agent settings. On other systems, the launchers and installed hooks run `dist/tripwire.js` with Bun. `TRIPWIRE_FORCE_PORTABLE=1` forces this fallback for diagnostics.

## Betterleaks

Post-tool scanning requires Betterleaks 1.5.0 or later on `PATH`, unless personal config sets an absolute executable path. Tripwire sends tool output on stdin and reads the JSON report from stdout. It does not use a shell or a temporary scan file.

Scanner execution has its own process timeout. Missing executables, timeouts, non-zero exits, and malformed reports produce a post-tool denial on hosts that support one.

## Shell parsing

Tripwire uses `unbash` 4.0.10 as its only Bash parser. It walks the typed AST, including lazy word parts and nested parse errors, then produces one security model for all rules. The model covers control flow, loops, cases, groups, subshells, substitutions, redirects, pipelines, static scalar assignments, local functions and aliases, wrapper commands, globs, and narrow same-program `mktemp` path provenance. Unresolved executable names, unresolved nested-shell source, `eval`, unresolved definitions, and computed policy discriminators fail closed.

The archive rule checks extraction mode and explicit destination flags. It does not inspect archive member paths.
