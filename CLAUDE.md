# tripwire

Opinionated Claude Code hooks dispatcher. One Bun entry point fronts every hook event in `~/.claude/settings.json`; rule modules decide allow / block / rewrite. Blocks return actionable error messages so the agent knows what to do next.

## Hard rules

- **Bun only, never npm.** `bun install`, `bun run <script>`, `bunx`. No `npm`, `npx`.
- **Effect v4 throughout.** Same patterns as `~/dev/vault/scripts/session-extract/extract.ts` — tagged errors, layered runtime, `Effect.timeout` on every rule, `Effect.exit` to isolate failures so one bad rule never blocks the agent.
- **Lint + typecheck clean before declaring done.** `bun run check` exits 0.
- **Hooks never throw to stderr or exit non-zero on internal error.** A buggy rule must default to `allow` and log to a file. A hung rule must hit its timeout and default to `allow`. The agent loop is more important than any single rule.
- **No JSON audit log, no mode toggle.** This is not a security framework — it's a scalpel for known-dangerous patterns. State out of scope.
- **Block messages are written for the agent, not the user.** When a rule blocks, the `permissionDecisionReason` must tell the agent the right alternative: "Use `rip` or `trash` instead of `rm`", "Use `fd` instead of `find`", not "denied for safety reasons".

## Build

```bash
bun install
bun run build      # → dist/tripwire.js (minified, bytecode-cached, executable shebang)
bun run check      # format + lint --fix + typecheck
bun test           # unit tests on rule modules
```

The compiled `dist/tripwire.js` is what `~/.claude/settings.json` invokes. Bun bytecode caching keeps per-call startup at single-digit ms.

## Wiring

`~/.claude/settings.json` calls the same binary for every hook event, dispatching by `hook_event_name` read from stdin:

```jsonc
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "/path/to/tripwire/dist/tripwire.js" }] },
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "/path/to/tripwire/dist/tripwire.js" }] },
    ],
  },
}
```

Settings.json stays one line per event. All policy lives in this repo, version-controlled.

## Layout

```
src/
  dispatch.ts        # entry — reads stdin, routes, writes JSON decision
  rules/
    bash-deny.ts     # rm -rf /, fork bomb, force push, dd of=/dev/, …
    bash-rewrite.ts  # find → fd, grep → rg (suggest, don't block)
    path-protect.ts  # .env, .ssh/, *.pem — block reads/writes by absolute path
    diff-aware.ts    # bad-words check on *added* lines only
  lib/
    decision.ts      # { kind: "allow" | "block" | "ask"; message?: string }
    log.ts           # one file at ~/.claude/tripwire.log, append-only, errors only
test/
  rules/*.test.ts    # one test file per rule, table-driven
```

## Rule contract

Every rule exports a single function:

```ts
type Rule = (input: HookInput) => Effect.Effect<Decision, never, never>;
```

- `never` in the error channel — a rule that can't decide returns `Decision.allow()`.
- The dispatcher composes rules with `Effect.timeout` (250ms each) and `Effect.exit`. A timeout or defect → `allow`, logged to `~/.claude/tripwire.log`.
- Rules are pure where possible. Side effects (filesystem reads to confirm `.env` exists) wrap in `Effect.gen` and use `BunFileSystem`.

## Block message style

Bad: `"Blocked: dangerous command"`
Good: `"rm is blocked outside /tmp and build directories. Use rip or trash for recoverable deletion, or scope rm to a known-safe path."`

The agent reads this verbatim and routes around it. Vague denials cause retry loops.

## Out of scope

- Audit logs, dashboards, stats — go use `aliou/pi-guardrails` if you want that.
- Mode toggles — if you need to disable a rule, edit the source.
- Secrets redaction in tool output — different concern; could live here later but not in v0.
- Per-project overrides — start with one user-wide policy. Project rules later if needed.
