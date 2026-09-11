# Embedded Python and JavaScript protection

Tripwire now inspects inline Python, JavaScript, and TypeScript before execution. A shell command such as `python3 -c 'import shutil; shutil.rmtree("/protected")'` reaches the same deletion policy as a direct shell deletion. The code inspector never runs submitted code.

## Parsing and policy

Unbash still owns shell syntax, quoting, wrappers, and command expansion. Its normalized redirects now retain heredoc content. The language carrier reader selects inline source from Python `-c`, Node/Bun `-e` and `--eval`, Deno `eval`, quoted heredocs, and literal here-strings. Source in a data command such as `cat` stays data.

Lezer parses the selected source into a syntax tree. The analyzer resolves a bounded subset: strings and common escapes, Python raw and triple-quoted strings, assignments, selected standard-library imports and aliases, JavaScript module destructuring, paths, and known calls. Python path composition has its own rules because an absolute component replaces the earlier prefix.

File reads retain a text type and their source path. JSON decoders produce inert data whose contents remain unknown. The analyzer permits indexing, dictionary summaries, selected string methods, JSON serialization, assertions, file context managers, simple formatted strings, and read-only processing of that data. Unknown data cannot become a filesystem path, a process argument, or a callable.

Python `for` and JavaScript `for…of` loops enumerate up to 128 literal values, or inspect a body against inert JSON data. For an unknown iteration count, bindings assigned in the body are invalidated before inspection. This prevents a safe alias on the first iteration from hiding a destructive call on a later iteration. Branches collect effects from every inspected body and merge differing bindings as unknown. Single-generator Python comprehensions inspect their expressions and filters.

The analyzer returns typed operations with source ranges: read, write, delete, truncate, and process arguments. File operations use Tripwire's path and read protections. Deletion and truncation also require a safe scope, checked against the real target and existing parent directories. Process arguments retain their argument boundaries and go back through the shell policy, including its Git rules. Child inspection stops after eight nested process boundaries.

Any analysis gap blocks the entire call. This includes unknown calls, computed access to executable modules, unsupported escapes, reflection, runtime code generation, callbacks, unsupported control flow, imports outside the supported modules, and file-backed scripts. The block describes what could not be inspected. A `tripwire-allow` comment cannot suppress this rule. Rule defects and timeouts also block this security rule; existing advisory-rule isolation remains intact.

The inspector checks options as well as function names. For example, a read with a write flag can truncate a file. Hex or base64 encoding can convert a nonempty string into an empty write. These options require review rather than inheriting the default call's classification.

An edit such as `p.write_text(p.read_text().replace("old", "new"))` is permitted because the replacement preserves a nonempty source and writes back to the same path. A replacement that could produce an empty file is classified as truncation. Python `re.sub` supports literal patterns and replacements; callbacks remain blocked, and backreferences cannot prove that output stays nonempty. JavaScript replacement tokens such as `$&` also lose that proof. Reads decoded with an encoding such as UTF-16LE cannot prove nonempty output. This proof does not require reading or executing the submitted source during policy evaluation.

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

Project package commands such as `bun build` and `bun test` retain their existing policy. Named `bun run` gates (`check`, `test`, `typecheck`, `lint`, `format`, `build`, `verify`, and colon-separated variants) use that same project-code trust boundary. These names are not evidence that the project's code is safe. Runtime preload options, arbitrary executables, and file paths do not enter the named-gate branch. Script files, Python `-m`, unsupported flags, and piped interpreter source still require review. Symlink checks are observations before execution and cannot eliminate filesystem races. Runtime containment remains necessary against a hostile process or concurrent filesystem mutation.

Writes with known nonempty content still follow the existing Write policy. This feature does not make an ordinary source-file overwrite recoverable, capture a diff, or authorize from an observed exit code. Those are separate activity and recovery concerns. Previewing a partial stream is also separate: authorization must inspect the complete final call.

## Validation and reproduction

The [11 September friction review](friction-2026-09-11.md) extends command classification for local Node/tsx and Deno checks, named Bun scripts with `--cwd`, shell name lookups, and explicit GitHub GET requests. Python text replacement also accepts a literal integer count. These additions retain the existing project-code trust boundary and add paired negative controls.

The `uv run` reader separates uv options from the launched command's arguments. It sends ordinary child commands through the shell policy, so a wrapped `rm` or Git mutation retains its protection. A `.py` argument owned by `pytest` is no longer mistaken for an interpreter launch. Inline Python and stdin source through uv require `--no-sync` and an existing trusted environment. Literal version selectors are supported; custom interpreter paths, dependency injection, directory changes, script files, and unknown uv options remain blocked. The [uv command reference](https://docs.astral.sh/uv/reference/cli/#uv-run) defines the option boundary and synchronization behavior.

Code-bearing invocations through Poetry, Pipenv, `npx`, and related launchers still require review. Versioned Python names include the free-threaded `t` suffix. Other arbitrary external launchers need a separate execution policy.

All new destructive fixtures are strings. Unit tests call the analyzer or dispatcher directly. Build smoke tests put those strings in JSON on Tripwire's stdin. The only launched executable is the trusted Tripwire runtime. The symlink test creates and later removes its own temporary directory and checks that its sentinel content stays unchanged.

`bun run verify` checks formatting, lint, types, the complete test suite, and both build outputs. The build sends all 301 corpus fixtures through each packaged hook: 139 original cases, 114 compatibility and adversarial cases, and 48 command-classification cases. The build also checks manifest-backed package scripts. The adversarial review suite adds option, alias, path, resource, and runtime-context cases. The Pi/OMP tests pass normalized events through the production hook and assert an actual embedded-code denial.

`test/fixtures/code-compatibility.ts` records rollout IDs and source locations for observed patterns. Paths and values are synthetic; adaptations and generated launch variants are labelled. `code-compatibility-attacks.ts` adds callback, alias, encoding, reflection, and wrapper attacks. `code-corpus.ts` supplies the shared build and benchmark corpus. These fixtures are not a statistical estimate of the false-positive rate across all sessions. Large scripts, custom imports, complex format specifications, glob-derived paths, and unresolved working directories remain outside the supported subset.

A frozen replay of local Astra and Fable calls dated 8–11 September 2026 restored 486 calls previously denied by the embedded-code rule. It also introduced 23 denials among previously allowed calls: five for unsupported uv options and 18 for an unverified working directory around a forwarded command. These remain compatibility costs. The replay extracted 14,720 shell calls and selected 6,544 interpreter/package-manager candidates; 312 computed wrapper calls could not be extracted statically. No rollout code was executed, and private rollout contents are not stored in this repository.

The full verification run passed 773 tests and all 301 fixtures through each of the native and portable packaged hooks. The build ran in a temporary copy and did not replace the installed hook. Review covers loop-carried aliases, JavaScript replacement tokens, regex backreferences, lossy decoding, write codecs, shared-value inspection budgets, command option ownership, and manifest validation.

Run `bun scripts/benchmark-code.ts` for the warm policy benchmark. A local run before the command-classification changes, on Bun 1.4.2, produced 5,060 samples over 253 fixtures: median 0.033 ms, p95 0.083 ms, p99 0.136 ms, maximum 2.015 ms. These historical measurements include Bash analysis and filesystem policy checks; they exclude process startup and do not measure the added command paths. The benchmark verifies each decision against its fixture expectation.

Before installing this change, review the intentional blocks on dynamic code and persistent REPLs. The implementation was built in an isolated worktree so validation did not replace the installed hook or alter host settings.
