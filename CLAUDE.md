# Tripwire contributor guide

Tripwire is a Bun and TypeScript hook dispatcher for Claude Code, Codex, Cursor Agent, Pi, and Oh My Pi. It applies deterministic rules to normalized tool events.

## Required commands

Use Bun 1.4 or later.

```bash
bun install --frozen-lockfile
bun run format:check
bun run lint
bun run typecheck
bun test
bun run build
bun run verify
```

`bun run verify` runs the non-mutating format check, lint, TypeScript 7 strict type check, all tests, and the build. Run it before release work. Use `bun run format` when files need formatting.

The runtime uses Effect 4.0.0-rc.112. Read the installed Effect source and types before changing an API that may differ from Effect 3 or an earlier release candidate.

## Package contract

The root registry package is portable. It contains a minified Bun runtime, a library bundle, declarations, runtime-selecting launchers, and the Pi adapter. It has no `os` or `cpu` restriction.

- `tripwire` maps to `dist/tripwire-cli.js`.
- `tripwire-hook` maps to `dist/tripwire-hook.js`.
- Both launchers select `@seanmozeik/tripwire-darwin-arm64` on Apple Silicon when it is available.
- All other hosts run `dist/tripwire.js` with Bun.
- The public import resolves to `dist/index.js` and `dist/types/index.d.ts` on every host.
- Host installers write the direct native executable path on Apple Silicon. This keeps live hook startup free of launcher overhead.

The `@seanmozeik/tripwire-darwin-arm64` workspace package has `os: [darwin]` and `cpu: [arm64]`. The root package lists the exact matching version as an optional dependency. Publish the platform package before the root package.

`scripts/build.ts` compiles to a temporary directory, runs executable and Pi adapter smoke tests, and publishes the files with same-directory atomic replacement. The build produces:

```text
dist/index.js
dist/tripwire.js
dist/tripwire-cli.js
dist/tripwire-hook.js
dist/tripwire-pi.js
dist/types/
packages/darwin-arm64/bin/tripwire
```

## Entry routing

`src/main.ts` is the only compiled entry point. It loads `src/dispatch.ts` for hooks and `src/cli.ts` for interactive commands. Keep the hook path small. Do not import CLI-only dependencies before entry routing.

The private flags are internal package contracts:

- `--tripwire-hook` selects hook mode and permits canonical event batches.
- `--tripwire-force-cli` selects CLI mode for the installed launcher and is removed before Effect CLI parses arguments.
- `--cursor-event <name>` supplies a missing Cursor event name.

## Rule contract

Rules are synchronous functions that return a `Decision`:

```ts
type DecisionKind = 'allow' | 'warn' | 'ask' | 'deny';
```

The dispatcher evaluates every applicable rule and uses the most restrictive result. Production hook evaluation uses a per-rule Effect boundary. If a rule throws, Tripwire logs the defect, treats only that rule as `allow`, and continues. The public synchronous `decide` function has the same throw isolation.

The Effect timeout does not interrupt synchronous CPU work. Do not describe it as an interruptible execution limit. A rule that needs a hard timeout must use an interruptible process or Effect.

Rule messages are read by an agent. A denial must name the rejected action and a safe next step.

Weak:

```text
Blocked: dangerous command
```

Useful:

```text
rm is blocked outside build and temporary paths. Use a recoverable deletion tool or limit the target to a configured safe path.
```

## Config contract

Personal policy lives in `~/.config/tripwire/config.json`. Open-source defaults do not require a package manager, search tool, branch model, or commit convention.

The config schema rejects unknown keys. Only `ENOENT` selects defaults. Invalid JSON, invalid values, permission errors, and other read errors are config failures.

Pre-tool evaluation denies when a present config fails to load. Post-tool evaluation still runs with the default scanner settings, so a broken config cannot skip secret scanning.

Supported config sections are:

- `git`
- `safePaths`
- `toolPolicies`
- `blockedCommands`
- `allowedCommands`
- `secretScanner`
- `shell.executionCarrierAliases`

Betterleaks 1.5.0 or later is the default post-tool scanner. It receives content on stdin and returns JSON on stdout. Scanner errors must not expose scanned text, secret values, or raw stderr.

## Host failure policy

- Native malformed single-event input returns an allow response and logs the error.
- A malformed private batch is denied.
- Invalid Cursor pre-tool input is denied. Cursor post-tool output cannot be replaced after execution.
- Pi and Oh My Pi deny pre-tool calls when the dispatcher fails or returns invalid output.
- Pi and Oh My Pi abort the session after a post-tool denial or dispatcher failure.
- A PowerShell pre-tool call is denied because there is no PowerShell parser. PowerShell post-tool output is scanned.

Do not change a host failure policy without a lifecycle test.

## Shell and path checks

`src/lib/bash/` uses `unbash` 4.0.10 as its only Bash parser. One exhaustive AST pass produces typed shell values, normalized executable invocations, redirects, pipelines, inspection diagnostics, and same-program temporary-path provenance. Rules consume that shared program model.

Parse errors, unresolved executable names, unresolved nested-shell source, `eval`, unresolved function or alias execution, and computed policy discriminators fail closed. Static scalar assignments, conditionals, loops, cases, brace groups, subshells, substitutions, local functions, and local aliases expose every executable node to the normal policy rules. Do not reparse quoted data or literal heredoc bodies as commands.

The tar rule checks extraction flags and explicit destinations. It denies `tar` extraction to `/` or the home directory and applies the same destination rule to `unzip -d`. It does not inspect archive member paths.

Protected-path rules compare submitted paths with resolved targets. New writes resolve the deepest existing parent. Keep read, write, edit, redirect, copy, and move classification on the shared path helper.

A shell bypass must match this form:

```text
# tripwire-allow: non-empty reason
```

Bare and empty markers do not bypass a rule. Catastrophic rules remain non-bypassable.

## Installer contract

Installer functions accept one options shape with an injectable home directory. Tests must use temporary homes.

All JSON and TOML files are parsed before the first write. Text settings use same-directory atomic replacement, preserve an existing file mode, and follow a config symlink to its real target. Unknown JSON fields and unrelated TOML bytes must remain.

Codex validates `hooks.json` and `config.toml` before it writes either file. It writes hooks first, then enables the feature. A retry repairs a first-file-only state.

Pi makes the extension link available before it removes old hook settings. Oh My Pi uses the same extension adapter path and has no settings rewrite.

## Source layout

```text
src/
  bin/
    cli.ts                   interactive runtime launcher
    hook.ts                  hook runtime launcher
  main.ts                  entry routing
  cli.ts                   test and install commands
  dispatch.ts              event decoding, rule isolation, host responses
  pi-extension.ts          Pi and Oh My Pi lifecycle adapter
  lib/
    bash.ts                shell parsing and command extraction
    config.ts              strict personal config loader
    cursor.ts              Cursor event normalization
    decision.ts            decision values and merge order
    event.ts               canonical event schema and response extraction
    install.ts             atomic host installers
    log.ts                 best-effort error log
    environment.ts         runtime environment boundary
    runtime-command.ts     native or portable runtime selection
    secrets.ts             Betterleaks process and redaction
  rules/                   pre-tool and post-tool rules
scripts/
  build.ts                 staged native, portable, library, and adapter build
packages/
  darwin-arm64/            optional Apple Silicon executable package
test/
  package.test.ts          bin and launcher contract
  pi-lifecycle.test.ts     source and compiled Pi lifecycle
  security-regressions.test.ts
  runtime-isolation.test.ts
```

## Review limits

Keep personal workflow rules in config. Keep source defaults useful for an unconfigured public install.

Add a focused regression test for each bug. Run the full verification command after focused tests pass.

Do not publish, push, or tag a release unless the task gives explicit permission.
