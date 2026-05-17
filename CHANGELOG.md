# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-15

### Added

- Synchronous rule engine execution for reliable and consistent CLI operation.
- New flag matching capabilities allowing rules to dynamically respond to command-line flags and their values.
- Documentation for known host-specific quirks and recommended configurations.

### Changed

- Updated the configuration decision process to utilize synchronous evaluation and pattern matching.
- Expanded README with new usage examples and setup guidelines.

## [0.2.0] - 2026-05-10

### Added

- New `install` subcommand to automatically configure AI agent hooks for Claude, Pi, and Codex.

### Changed

- Migrated CLI argument parsing to the Effect CLI library for improved stability and consistency.

## [0.1.0] - 2026-05-10

### Added

- JSON-based configuration system for defining custom safety rules.
- Smart Git policy with conventional commit message enforcement in bash scripts.

### Fixed

- Bash syntax handling now correctly preserves pipe operators (`|&`, `>|`) and inner command segments instead of hiding them.
- Properly recognizes file descriptor-prefixed redirects and merged `&>` operations in bash.
