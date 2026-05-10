# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-10

### Added
- JSON-based configuration system for defining custom safety rules.
- Smart Git policy with conventional commit message enforcement in bash scripts.

### Fixed
- Bash syntax handling now correctly preserves pipe operators (`|&`, `>|`) and inner command segments instead of hiding them.
- Properly recognizes file descriptor-prefixed redirects and merged `&>` operations in bash.

