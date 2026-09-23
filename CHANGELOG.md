# Changelog

This file records notable project changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-09-23

### Added

- Inspect inline functions as values. Arrow functions, function declarations, `def`, `lambda`, plain classes, and callbacks passed to builtins are analyzed with their real arguments and lexical scope, and callbacks that can run many times are treated like loops.
- Support ordinary inline data code: comprehensions, tuple and rest bindings, `try`/`except`/`finally`, `while`, `throw`/`raise`, walrus assignments, template and f-strings, `null`, `new Date()`, regex literals, and per-function contracts for common standard-library modules. Importing a module does not authorize its members.
- Bind trailing interpreter arguments to `sys.argv` and `process.argv`.
- Unwrap `mise exec`, `direnv exec`, `dotenv`, `op run`, `doppler run`, `infisical run`, `aws-vault exec`, `nix develop`, `nix-shell`, `devbox`, `pixi`, `pdm`, `hatch`, `conda run`, `fnm`, `asdf`, `rbenv`, `pyenv`, `volta`, `caffeinate`, `corepack`, `uvx`, `busybox`, and `toybox`. Every other rule checks the inner command. Wrappers that load project environments mark inline startup as unverified unless mise configuration can be checked statically.

### Changed

- Inspect safe `mise exec` and `mise x` inline interpreters using static TOML, dotenv, profile, parent/global/system config, and backend checks. Never execute mise, templates, or plugins during inspection; reject unverified startup effects.
- Supply real items to builtin callbacks and comprehensions over precise lists of at most 128 items, carrying reducer accumulators and preserving mutation safeguards.
- Track the working directory through literal `cd`, `pushd`, `popd`, subshells, and wrappers, and apply it to every path rule. An unknown directory blocks relative operations and is carried into forwarded commands.
- Expand `~` from a tracked `HOME`. A dynamic or unset `HOME` fails closed.
- Route inline rename, copy, move, and symlink calls through the shell transfer policy, so they get the same decision as `mv`, `cp`, and `ln`.
- Limit inline evaluation by CPU time, and bound shell glob expansion: recursive patterns and relative patterns in an unknown directory are not expanded.

### Fixed

- Report inline syntax errors with language, line, column, and a bounded excerpt. Explain literal `\n` in single shell quotes and identify unexpected failures as internal inspector errors.
- Isolate tests from the developer's home, launch directory, temporary-directory contents, and executable overrides. Replace elapsed-time assertions with inspection-budget outcomes.
- Protect directory destinations for `mv`, `cp`, `ln`, `rsync`, and `install`. `mv x ~/.ssh` and `cp x ~/.ssh/` were allowed.
- Block tool wrappers that previously hid the inner command, such as `mise x -- rm -rf /`.
- Stop checking forwarded commands against the hook directory after an unknown `cd`.
- Keep redirect targets when `xargs` forwards to a package runner.
- Allow read-only `git branch` forms with a computed `-C`.
- Classify relative deletions after `cd` by their resolved location.

## [0.10.0] - 2026-09-15

### Changed

- Limit interpreter inspection to inline source. Allow script files, Python modules, named package scripts, formatters, compilers, and test runners.
- Preserve shell argument values and execution context through package wrappers. Keep destructive-command, Git, and protected-file checks active.

### Added

- Support inline Bun JSON-file reads, Python hashing, common uv wrapper options, and parsed GraphQL queries.

### Fixed

- Check startup options for inline stdin source and retain working-directory restrictions through package wrappers.
- Inspect shell source supplied through stdin device paths.

## [0.9.2] - 2026-09-12

### Fixed

- Support common inline Python ZIP reads and writes, directory listings, text diffs, text encoding, and writes filtered to a fixed list of filenames. Apply file policy to archive paths, source files, and output destinations.
- Support local JavaScript JSON-file imports as data, with the existing protected-file read checks.
- Verify that JSON imports resolve to regular JSON files, rejecting directories and links to executable modules.
- Normalize supported keyword arguments against library call signatures and share standard codec validation between file operations and text conversion.

## [0.9.1] - 2026-09-12

### Fixed

- Allow direct execution of local Python, JavaScript, and TypeScript files without a review marker, including supported Bun, Deno, and uv run commands. File contents and imports use the same trust boundary as project scripts.
- Apply reason-bearing review markers to interpreter invocation restrictions. Continue to check separate shell commands and inspected inline code for destructive operations.

## [0.8.0] - 2026-08-31

### Added

- Added an AST-backed Bash security model with typed values, nested invocation discovery, static scalar, local function, and alias binding, and narrow same-program temporary-path provenance.
- Added a reduced rollout corpus with safe and adversarial cases for control flow, loops, groups, subshells, command and process substitutions, quoting, Git policy, redirects, wrappers, and temporary paths.
- Added configurable SSH-equivalent execution carriers, bounded literal base64 shell-input inspection, fixed-list loop values, static scalar path composition, and same-program background PID capabilities.
- Added `tripwire run-script` to inspect one script snapshot and execute those exact bytes with Bash.
- Added typed personal action overrides for workflow-policy rules such as `no-verify`. Safety invariants are not configurable.

### Changed

- Replaced `shell-quote` and the separate shell scanners with `unbash` 4.0.10 as the only Bash parser.
- Updated de-clank to 0.1.8 and moved Bash analysis into one module directory.

### Fixed

- Allowed inspectable compound shell programs while keeping malformed syntax, dynamic execution, dynamic shell source, and `eval` fail-closed.
- Kept computed policy discriminators fail-closed and denied mutating `gh api` requests that could bypass Git workflow policy.
- Allowed `git clean -dn` previews while keeping destructive clean operations denied.
- Classified `git diff-tree`, `git write-tree`, read-only `git remote` inspection, and `git checkout-index` explicitly. Read-only `dd if=...` input remains allowed when no computed output target can be hidden.
- Made source-dispatch tests use the current Bun executable when they run with an isolated home directory.

## [0.7.1] - 2026-08-27

### Added

- Added a minified Bun runtime bundle for Linux, Windows, and Intel macOS.
- Added a platform-neutral library bundle and TypeScript declarations for package imports.
- Added runtime-selecting launchers and Pi adapter support for native and portable installations.

### Changed

- Moved the Apple Silicon bytecode executable into the optional `@seanmozeik/tripwire-darwin-arm64` package.
- Removed the operating system and CPU restrictions from the main package.
- Updated host installers to write the direct native executable path when it is available.

## [0.7.0] - 2026-08-27

### Added

- Added native Pi and Oh My Pi extensions with batched multi-file policy checks.
- Added Betterleaks 1.5.0 or later as the configurable post-tool secret scanner.
- Added Cursor Agent hook support.
- Added the MIT license and complete registry metadata.

### Changed

- Updated the build to [Bun 1.4](https://bun.com/blog/bun-v1.4). The package contains one bytecode executable for Darwin arm64 and a separate bundled Pi adapter. Live hooks point directly to the executable.
- Updated Effect and Platform Bun to [4.0.0-rc.112](https://github.com/Effect-TS/effect/releases/tag/effect%404.0.0-rc.112). `Effect.try` error channels use `Data.TaggedError`, and the CLI post-tool flag has an explicit `Flag.withDefault(false)` value.
- Pinned [TypeScript 7.0.2](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/) in strict mode. Bun globals now come from `bun-types` instead of `@types/bun`. The compiler config keeps explicit Bun types and output exclusions.
- Updated Oxlint to [1.80.0](https://github.com/oxc-project/oxc/releases/tag/oxlint_v1.80.0), Oxfmt to 0.65.0, and Effect TSGo to 0.38.0. The lint command no longer passes a separate TypeScript config. The project composes de-clank 0.1.7 core and Effect configs with its local rules.
- Moved package-manager, search-tool, branch, and commit preferences from source rules to personal config.
- Restricted registry installation to Darwin arm64. Other systems build from source.
- Added local format checking and one `verify` command for all release gates.

### Fixed

- Isolated rule failures so one thrown rule does not suppress later policy decisions.
- Distinguished missing personal config from invalid, unreadable, and unknown config values.
- Kept post-tool secret scanning active when personal config cannot load.
- Denied unsupported PowerShell pre-tool calls and scanned PowerShell post-tool output.
- Closed compound-shell, negation, protected-path symlink, bypass-marker, and tar-listing policy gaps.
- Made scanner failures return a post-tool denial without exposing scanned data or raw scanner errors.
- Made host settings replacement atomic while preserving file modes, unknown fields, unrelated TOML bytes, and existing config symlinks.

## [0.6.7] - 2026-07-29

### Changed

- Updated the Effect and TypeScript development toolchain.

## [0.6.6] - 2026-06-22

### Added

- Added Tripwire feature documentation and usage examples.

### Fixed

- Added a policy check for ripgrep `-r` flag misuse.

## [0.6.5] - 2026-06-08

### Fixed

- Corrected the ripgrep `-r` flag description.

## [0.6.4] - 2026-06-07

### Fixed

- Made invalid config fail loudly instead of selecting defaults.

## [0.6.3] - 2026-06-07

### Fixed

- Split newline shell statements without changing quoted text.

## [0.6.2] - 2026-06-05

### Added

- Added grep flag normalization, sensitive-path checks, privilege-escalation checks, and `poke run` wrapper inspection.

### Changed

- Normalized shell command heads to executable base names.

## [0.5.3] - 2026-05-26

### Fixed

- Corrected hook path resolution for script and bundled execution.

## [0.5.2] - 2026-05-26

### Changed

- Resolved the dispatcher path at CLI runtime.

## [0.5.1] - 2026-05-24

### Fixed

- Kept heredoc content visible to bypass-marker checks.

## [0.5.0] - 2026-05-22

### Added

- Added inline `sh -c` and `bash -c` analysis, quote-aware command substitutions, heredoc handling, and `source` command denial.

### Fixed

- Corrected quote, backtick, command-substitution, and heredoc boundary handling.

## [0.4.1] - 2026-05-17

### Added

- Added safety checks for commands executed through `fd -x` and `find -exec`.

## [0.4.0] - 2026-05-15

### Added

- Added synchronous rule execution and flag-value matching.

## [0.2.0] - 2026-05-10

### Added

- Added the `install` command for Claude Code, Pi, and Codex.

### Changed

- Migrated CLI argument parsing to Effect CLI.

## [0.1.0] - 2026-05-10

### Added

- Added JSON configuration and Git policy checks.

### Fixed

- Preserved pipe and redirect operators during shell parsing.
