# Embedded Python and JavaScript protection

Tripwire now inspects inline Python, JavaScript, and TypeScript before execution. A shell command such as `python3 -c 'import shutil; shutil.rmtree("/protected")'` reaches the same deletion policy as a direct shell deletion. The code inspector never runs submitted code.

## Parsing and policy

Unbash still owns shell syntax, quoting, wrappers, and command expansion. Its normalized redirects now retain heredoc content. The language carrier reader selects inline source from Python `-c`, Node/Bun `-e` and `--eval`, Deno `eval`, quoted heredocs, and literal here-strings. Source in a data command such as `cat` stays data.

Lezer parses the selected source into a syntax tree. The analyzer resolves a bounded subset: strings and common escapes, Python raw and triple-quoted strings, assignments, selected standard-library imports and aliases, JavaScript module destructuring, paths, and known calls. Python path composition has its own rules because an absolute component replaces the earlier prefix.

File reads produce a text or data value. JSON decoders produce inert data whose contents remain unknown. The analyzer permits indexing, dictionary summaries, selected string methods, JSON serialization, assertions, file context managers, simple formatted strings, and processing of that data. Unknown data cannot become a filesystem path, a process argument, or a callable.

Python `for` and JavaScript `for…of` loops enumerate up to 128 literal values, or inspect a body against inert JSON data. For an unknown iteration count, bindings assigned in the body are invalidated before inspection. This prevents a safe alias on the first iteration from hiding a destructive call on a later iteration. Branches collect effects from every inspected body and merge differing bindings as unknown. Single-generator Python comprehensions inspect their expressions and filters.

The analyzer returns typed operations with source ranges: read, write, delete, truncate, and process arguments. File operations use Tripwire's path and read protections. Deletion and truncation also require a safe scope, checked against the real target and existing parent directories. Process arguments retain their argument boundaries and go back through the shell policy, including its Git rules. Child inspection stops after eight nested process boundaries.

An analysis gap in inline source blocks the call. This includes unknown calls, computed access to executable modules, unsupported escapes, reflection, runtime code generation, callbacks, unsupported control flow, and imports outside the supported modules. File-backed execution is outside this analysis. The block describes what could not be inspected. An inline analysis denial cannot be suppressed with a comment. Rule defects and timeouts also block this security rule; existing advisory-rule isolation remains intact.

The inspector checks options as well as function names. A read submitted with a write flag still requires review. Normal Node writes accept built-in encodings and supported write/append flags. Python file calls accept a supported `encoding` keyword, and JSON serialization accepts an inert `indent` keyword. Custom codecs, file openers, callbacks, and unknown options require review because they can introduce uninspected effects.

Normal file writes follow the same destination policy as the dedicated Write tool. This includes overwrites, empty content, JSON output, copies from other files, regex substitutions, slices, and `open(path, "w")`. The language and output length do not impose an extra deletion rule. Explicit operations such as `unlink`, `rmtree`, `os.truncate`, and `fs.truncateSync` still require a verified safe scope. Protected destinations and symlink targets remain blocked. This is path-policy parity, not recovery for overwritten content.

## Dependency decision

Research and package resolution on 11 September 2026 selected these exact versions:

| Dependency          | Version | Purpose                           |
| ------------------- | ------- | --------------------------------- |
| `@lezer/python`     | 1.1.19  | Python grammar                    |
| `@lezer/javascript` | 1.5.4   | JavaScript and TypeScript grammar |
| `@lezer/common`     | 1.5.2   | Typed syntax-tree access          |

The [Python grammar](https://github.com/lezer-parser/python) and [JavaScript grammar](https://github.com/lezer-parser/javascript) document MIT licensing; the JavaScript package exposes a TypeScript dialect. The GitHub repositories point to their new upstream locations. The installed package READMEs and declarations were also inspected.

[Oxc](https://oxc.rs/docs/guide/usage/parser.html) is a strong Rust JavaScript/TypeScript parser with native Node bindings. It does not supply Python parsing. [Web Tree-sitter](https://github.com/tree-sitter/tree-sitter/blob/master/lib/binding_web/README.md) supplies WASM parsing with separate language artifacts and initialization. Both remain valid choices for a Rust activity-analysis service.

Tripwire already has synchronous TypeScript rules and standalone Bun native and portable outputs. Lezer gives these outputs one common parser interface without a new native helper or runtime grammar files. The complete fixture corpus passed in both bundled outputs. This is a packaging and measured-latency choice, not an unmeasured claim that Lezer is universally fastest. This change adds TypeScript to Tripwire; it does not replace the separate Rust activity prototype.

## Bounds and trust assumptions

Source is limited to 65,536 UTF-16 code units. Trees are limited to 12,000 nodes and depth 80. Evaluation stops after 12,000 steps, including loop bodies. Each call accepts at most 128 arguments. Resolved strings are limited to 65,536 code units, with a one-million-code-unit evaluation budget. An iterative data walk checks shared values once and stops after 12,000 values. Parsing uses strict mode and a 40 ms cooperative deadline. This deadline is checked between parser steps and during tree inspection; it cannot preempt a parser step on the same thread.

The guard assumes the selected local interpreter and supported standard-library modules are trusted. It cannot prove the contents of a modified Python installation, startup hooks already present in the host environment, or monkey-patched Node builtins. Explicit startup overrides in the submitted shell program, directory changes, and remote execution block code inspection because its local context is no longer sufficient.

Known persistent REPL tools block because this stateless hook cannot verify earlier bindings. Supporting them safely requires runtime identity and state tracking at the host boundary. Direct source tools are normalized for inspection, but the host must supply the complete final source before execution and use a fresh trusted runtime. An unknown tool name is outside this adapter contract. A shell running inside a container or another arbitrary launcher is also outside the new language carrier set.

Script files, Python modules, package commands, tests, formatters, and compilers pass the inline-code rule. Their names and flags are not proof of safety. The carrier reader identifies inline source and stops at a file, module, or named script. It does not read a package manifest to approve script names. Shell file execution, including sourcing a file, uses the same boundary. Unavailable piped inline source remains blocked. File contents and dependency behavior are outside this tool's inspection scope.

`Bun.file(path).json()` produces inert data, and `.text()` produces inert text. Both register a read against the path policy. Python `hashlib` constructors produce a hash value with supported `update`, `copy`, `digest`, and `hexdigest` methods. Byte literals, JSON fields, and hash output remain data; they cannot authorize an unknown path or dynamic call.

Writes with inert content follow the existing Write policy even when their output bytes are unknown. This feature does not make an ordinary source-file overwrite recoverable, capture a diff, or authorize from an observed exit code. Those are separate activity and recovery concerns. Previewing a partial stream is also separate: authorization must inspect the complete final call.

## Validation and reproduction

The [11 September friction review](friction-2026-09-11.md) extends command classification for local Node/tsx and Deno checks, named Bun scripts with `--cwd`, shell name lookups, and explicit GitHub GET requests. Python text replacement also accepts a literal integer count. These additions retain the existing project-code trust boundary and add paired negative controls.

The `uv run` reader separates wrapper options from child arguments. It supports `--locked`, `--no-dev`, project selection, and file/module commands. Ordinary inline source does not require `--no-sync`. Explicit custom runtime selection, dependency injection, or changed working directories still prevent local inline inspection. Setup commands and file-backed scripts have their normal tool policy. Wrapped shell commands and deletions retain checks when the wrapper changes their execution context.

Package launchers expose a child interpreter's inline source for inspection. A formatter's filename arguments are not interpreter source. GitHub GraphQL fields use the GraphQL parser: every operation in an allowed document must be a query. Fragments are supported; mutations, subscriptions, malformed documents, duplicate query fields, and file-backed request bodies remain blocked.

Code-bearing invocations through Poetry, Pipenv, `npx`, and related launchers still require review. Versioned Python names include the free-threaded `t` suffix. Other arbitrary external launchers need a separate execution policy.

All new destructive fixtures are strings. Unit tests call the analyzer or dispatcher directly. Build smoke tests put those strings in JSON on Tripwire's stdin. The only launched executable is the trusted Tripwire runtime. The symlink test creates and later removes its own temporary directory and checks that its sentinel content stays unchanged.

`bun run verify` checks formatting, lint, types, the complete test suite, and both build outputs. The build sends the complete `code-corpus.ts` fixture list through each packaged hook, including `inline-scope.ts` regressions from the 8–15 September audit. The build also checks named package-script execution. The Pi/OMP tests pass normalized events through the production hook and assert an actual embedded-code denial. All destructive command examples remain inert policy inputs.

`test/fixtures/code-compatibility.ts` records rollout IDs and source locations for observed patterns. Paths and values are synthetic; adaptations and generated launch variants are labelled. `code-compatibility-attacks.ts` adds callback, alias, encoding, reflection, and wrapper attacks. `code-corpus.ts` supplies the shared build and benchmark corpus. These fixtures are not a statistical estimate of the false-positive rate across all sessions. Large scripts, custom imports, complex format specifications, glob-derived paths, and unresolved working directories remain outside the supported subset.

A frozen replay of local Astra and Fable calls dated 8–11 September 2026 restored 486 calls previously denied by the embedded-code rule. It also introduced 23 denials among previously allowed calls: five for unsupported uv options and 18 for an unverified working directory around a forwarded command. These remain compatibility costs. The replay extracted 14,720 shell calls and selected 6,544 interpreter/package-manager candidates; 312 computed wrapper calls could not be extracted statically. No rollout code was executed, and private rollout contents are not stored in this repository.

The full verification run passed 829 tests and all 355 fixtures through each of the native and portable packaged hooks. The build ran in a temporary copy and did not replace the installed hook. Review covers loop-carried aliases, destination-policy parity, protected-path symlinks, explicit deletion and truncation, write codecs, shared-value inspection budgets, command option ownership, and manifest validation.

Run `bun scripts/benchmark-code.ts` for the warm policy benchmark. A local run before the command-classification changes, on Bun 1.4.2, produced 5,060 samples over 253 fixtures: median 0.033 ms, p95 0.083 ms, p99 0.136 ms, maximum 2.015 ms. These historical measurements include Bash analysis and filesystem policy checks; they exclude process startup and do not measure the added command paths. The benchmark verifies each decision against its fixture expectation.

Before installing this change, review the intentional blocks on dynamic code and persistent REPLs. The implementation was built in an isolated worktree so validation did not replace the installed hook or alter host settings.
