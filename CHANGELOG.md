# Changelog

This file records notable project changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added native Pi and Oh My Pi extensions with batched multi-file policy checks.
- Added Betterleaks 1.5.0 or later as the configurable post-tool secret scanner.
- Added Cursor Agent hook support.
- Added the MIT license and complete registry metadata.

### Changed

- Updated the build to [Bun 1.4](https://bun.com/blog/bun-v1.4). The package contains one bytecode executable for Darwin arm64 and a separate bundled Pi adapter. Live hooks point directly to the executable.
- Updated Effect and Platform Bun to [4.0.0-rc.112](https://github.com/Effect-TS/effect/releases/tag/effect%404.0.0-rc.112). Hook execution, process use, CLI commands, and schemas use the current Effect APIs.
- Updated the project to [TypeScript 7](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/) strict mode. The compiler config declares the Bun types, source root, and generated output exclusions.
- Updated Oxlint to [1.80.0](https://github.com/oxc-project/oxc/releases/tag/oxlint_v1.80.0), Oxfmt to 0.65.0, and Effect TSGo to 0.38.0. The lint config uses de-clank 0.1.7 with its Effect preset.
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
