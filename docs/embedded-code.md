# Embedded Python and JavaScript protection

Tripwire now inspects inline Python, JavaScript, and TypeScript before execution. A shell command such as `python3 -c 'import shutil; shutil.rmtree("/protected")'` reaches the same deletion policy as a direct shell deletion. The code inspector never runs submitted code.

## Parsing and policy

Unbash still owns shell syntax, quoting, wrappers, and command expansion. Its normalized redirects now retain heredoc content. The language carrier reader selects inline source from Python `-c`, Node/Bun `-e` and `--eval`, Deno `eval`, quoted heredocs, and literal here-strings. Source in a data command such as `cat` stays data.

Lezer parses the selected source into a syntax tree. The analyzer resolves a deliberately bounded subset: plain strings, string concatenation, assignments, selected standard-library imports, import aliases, JavaScript module destructuring, paths, and known calls. Python path composition has its own rules because an absolute component replaces the earlier prefix.

The analyzer returns typed operations with source ranges: read, write, delete, truncate, and process arguments. File operations use Tripwire's path and read protections. Deletion and truncation also require a safe scope, checked against the real target and existing parent directories. Process arguments retain their argument boundaries and go back through the shell policy, including its Git rules. Child inspection stops after eight nested process boundaries.

Any analysis gap blocks the entire call. This includes unknown calls, computed members, escaped literals, reflection, runtime code generation, callbacks, unsupported control flow, imports outside the supported modules, and file-backed scripts. The block describes what could not be inspected. A `tripwire-allow` comment cannot suppress this rule. Rule defects and timeouts also block this security rule; existing advisory-rule isolation remains intact.

The inspector checks options as well as function names. For example, a read with a write flag can truncate a file. Hex or base64 encoding can convert a nonempty string into an empty write. These options require review rather than inheriting the default call's classification.

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

Source is limited to 65,536 UTF-16 code units. Trees are limited to 12,000 nodes and depth 80. Each call accepts at most 128 arguments. Resolved strings are limited to 65,536 code units, with a one-million-code-unit evaluation budget. Parsing uses strict mode and a 40 ms cooperative deadline. This deadline is checked between parser steps and during tree inspection; it cannot preempt a parser step on the same thread.

The guard assumes the selected local interpreter and supported standard-library modules are trusted. It cannot prove the contents of a modified Python installation, startup hooks already present in the host environment, or monkey-patched Node builtins. Explicit startup overrides in the submitted shell program, directory changes, and remote execution block code inspection because its local context is no longer sufficient.

Known persistent REPL tools block because this stateless hook cannot verify earlier bindings. Supporting them safely requires runtime identity and state tracking at the host boundary. Direct source tools are normalized for inspection, but the host must supply the complete final source before execution and use a fresh trusted runtime. An unknown tool name is outside this adapter contract. A shell running inside a container or another arbitrary launcher is also outside the new language carrier set.

Project package commands such as `bun build` and `bun test` retain their existing policy. They can execute project code; this feature does not make that code a sandbox. Script files, Python `-m`, unsupported flags, and piped interpreter source block instead of reading a file now and assuming the same bytes will execute later. Symlink checks are observations before execution and cannot eliminate filesystem races. Runtime containment remains necessary against a hostile process or concurrent filesystem mutation.

Writes with known nonempty content still follow the existing Write policy. This feature does not make an ordinary source-file overwrite recoverable, capture a diff, or authorize from an observed exit code. Those are separate activity and recovery concerns. Previewing a partial stream is also separate: authorization must inspect the complete final call.

## Validation and reproduction

All new destructive fixtures are strings. Unit tests call the analyzer or dispatcher directly. Build smoke tests put those strings in JSON on Tripwire's stdin. The only launched executable is the trusted Tripwire runtime. The symlink test creates and later removes its own temporary directory and checks that its sentinel content stays unchanged.

`bun run verify` checks formatting, lint, types, the complete test suite, and both build outputs. The build sends all 139 primary fixtures through each packaged hook. The adversarial review suite adds option, alias, path, resource, and runtime-context cases. The Pi/OMP tests pass normalized events through the production hook and assert an actual embedded-code denial.

Run `bun scripts/benchmark-code.ts` for the warm policy benchmark. One local run on Bun 1.4.2 produced 2,780 samples: median 0.034 ms, p95 0.125 ms, p99 0.435 ms, maximum 9.764 ms. These measurements include Bash analysis and filesystem policy checks; they exclude process startup and do not compare parser implementations. The benchmark also verifies each decision against its fixture expectation.

Before installing this change, review the intentional blocks on dynamic code and persistent REPLs. The implementation was built in an isolated worktree so validation did not replace the installed hook or alter host settings.
