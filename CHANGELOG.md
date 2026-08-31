# Changelog

This file records notable project changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
