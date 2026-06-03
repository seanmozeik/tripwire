// Generic bash command parsing built on `shell-quote`. Used by every bash
// Rule — bash-deny, bash-scoped-rm, bash-redirect, bash-network-install,
// Bash-tar-explosion, bash-tool-policy.
//
// Shell-quote.parse(cmd) returns a flat array of tokens and operator
// Objects. We post-process it into structured `Segment`s split at top-level
// Shell operators (`;`, `&&`, `||`, `|`, `&`, newline). Each segment
// Records its head token, positional args, flags, and redirect targets.
//
// Limitations:
//   - No variable expansion. `$HOME` stays literal — rules that care about
//     Paths should either reject literal env-var references or accept them.
//   - Command substitution `$(...)` is collapsed into a single opaque
//     Token (`__tripwire_cmd_sub__`) so safe-path checks fail safely.
//   - Glob expansion is not performed.

import { parse, type ParseEntry } from 'shell-quote';

interface Segment {
  readonly head: string; // First non-flag token, e.g. `rm`, `npm`
  readonly tokens: readonly string[]; // All string tokens incl. head, in order
  readonly args: readonly string[]; // Tokens[1..], minus pure flag tokens
  readonly flags: readonly string[]; // Tokens that start with `-`
  readonly redirects: readonly Redirect[];
  readonly raw: string; // Best-effort reconstruction
}

interface Redirect {
  readonly op: '>' | '>>' | '<' | '<<' | '<<<' | '<>' | '>&' | '<&' | '&>' | '&>>';
  readonly target: string;
}

const SAFE_RELATIVE: readonly string[] = [
  'dist',
  'build',
  '_build',
  'out',
  'target',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.output',
  '.astro',
  '.angular',
  '.vite',
  '.parcel-cache',
  '.turbo',
  '.vercel',
  '.netlify',
  '.fly',
  '.wrangler',
  '.serverless',
  'coverage',
  '.nyc_output',
  '.cache',
  '.ruff_cache',
  '.mypy_cache',
  '.pytest_cache',
  '.ty_cache',
  '.tox',
  '__pycache__',
  '.venv',
  'venv',
  'node_modules',
  '.gradle',
  'DerivedData',
  '.bundle',
  '.cargo-target',
  'tmp',
  '.tmp',
  '.state',
  '.terraform',
  '.yarn/cache',
  '.yarn/install-state.gz',
  '.pnpm-store',
  '.bun',
];

const SAFE_ABSOLUTE: readonly string[] = [
  '/tmp',
  '/var/tmp',
  '/var/folders',
  '/private/tmp',
  '/private/var/tmp',
  '/private/var/folders',
];

const REDIRECT_OPS: ReadonlySet<string> = new Set([
  '>',
  '>>',
  '<',
  '<<',
  '<<<',
  '<>',
  '>&',
  '<&',
  '&>',
  '&>>',
]);

// `|&` is bash shorthand for "pipe stdout AND stderr to the next command"
// — semantically equivalent to `2>&1 |` for our purposes. shell-quote
// Emits it as a single op; without classifying it as a segment break,
// `cmd1 |& cmd2` collapses into one segment with `__op_|&__` as a fake
// Positional arg, hiding `cmd2` from every rule.
const SEGMENT_OPS: ReadonlySet<string> = new Set([';', '&&', '||', '|', '|&', '&']);

// Type guards over `ParseEntry`.
const isStringToken = (e: ParseEntry): e is string => typeof e === 'string';
const getOp = (e: ParseEntry): string | null => {
  if (typeof e === 'object' && 'op' in e && typeof e.op === 'string') {
    return e.op;
  }
  return null;
};
const isCommentToken = (e: ParseEntry): boolean => typeof e === 'object' && 'comment' in e;

// Glob entries from shell-quote are `{ op: 'glob', pattern: '...' }`. We
// Expand them against the hook's cwd via `Bun.Glob` so safe-path rules
// See concrete files (e.g. `.state/foo*` → `.state/foo-1.json`,
// `.state/foo-2.json`) instead of an opaque `__op_glob__` sentinel that
// Always fails safe-path checks. If a pattern matches nothing, we keep
// The literal pattern so the rule can still reason about its prefix
// (e.g. `.state/foo*` resolves under `.state/` regardless).
const expandGlob = (pattern: string): string[] => {
  try {
    const matches = [...new Bun.Glob(pattern).scanSync({ onlyFiles: false, dot: true })];
    if (matches.length > 0) {
      return matches;
    }
  } catch {
    // Fall through to the literal pattern.
  }
  return [pattern];
};

// Convert one entry to one or more string tokens. Operators and
// Command-sub markers become opaque sentinel tokens; globs expand.
const entryToTokens = (e: ParseEntry): string[] => {
  if (isStringToken(e)) {
    return [e];
  }
  if (typeof e === 'object' && 'op' in e && e.op === 'glob' && 'pattern' in e) {
    return expandGlob(String((e as { pattern: unknown }).pattern));
  }
  const op = getOp(e);
  if (op !== null) {
    if (REDIRECT_OPS.has(op) || SEGMENT_OPS.has(op)) {
      return [];
    }
    return [`__op_${op}__`];
  }
  if (isCommentToken(e)) {
    return [];
  }
  return ['__tripwire_cmd_sub__'];
};

interface FdBudget {
  remaining: number;
}

const parseSegment = (entries: readonly ParseEntry[], fdBudget: FdBudget): Segment | null => {
  const tokens: string[] = [];
  const args: string[] = [];
  const flags: string[] = [];
  const redirects: Redirect[] = [];

  let i = 0;
  while (i < entries.length) {
    const e = entries[i]!;
    const op = getOp(e);
    if (op !== null && REDIRECT_OPS.has(op)) {
      // Shell-quote emits a leading file-descriptor digit (e.g. the `2` in
      // `2>&1`) as a separate string token *before* the redirect op. It
      // Also drops the whitespace, so `echo 2 >file` and `echo 2>file`
      // Produce identical token streams. We pre-scanned the original
      // Command for digit-then-redirect-with-no-space patterns and stored
      // The count in fdBudget; only consume one when we see a digit
      // Adjacent to a redirect op here.
      const last = tokens.at(-1);
      if (last !== undefined && /^[0-9]+$/.test(last) && fdBudget.remaining > 0) {
        tokens.pop();
        fdBudget.remaining--;
      }
      const target = entries[i + 1];
      if (target !== undefined && isStringToken(target)) {
        redirects.push({ op: op as Redirect['op'], target });
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    for (const t of entryToTokens(e)) {
      tokens.push(t);
    }
    i++;
  }

  if (tokens.length === 0) {
    return null;
  }
  for (let j = 1; j < tokens.length; j++) {
    const t = tokens[j]!;
    if (t.startsWith('-') && t !== '-') {
      flags.push(t);
    } else {
      args.push(t);
    }
  }
  return { head: tokens[0]!, tokens, args, flags, redirects, raw: tokens.join(' ') };
};

// Pass an env function that preserves variable references as literals,
// Otherwise shell-quote treats `$HOME` as an empty string and we lose
// The ability to reason about home-directory references.
const PRESERVE_ENV = (key: string): string => `$${key}`;

// Shell-quote splits `&>file` into two ops — `{op:"&"}` then `{op:">"}` —
// Which would (a) make the `&` look like a backgrounding segment break and
// (b) hide the redirect from rule analysis. Merge those pairs back into
// `&>` / `&>>` before segment splitting.
const mergeAmpRedirects = (entries: readonly ParseEntry[]): ParseEntry[] => {
  const out: ParseEntry[] = [];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    const next = entries[i + 1];
    if (getOp(e) === '&' && next !== undefined && (getOp(next) === '>' || getOp(next) === '>>')) {
      const merged = { op: getOp(next) === '>' ? '&>' : '&>>' } as unknown as ParseEntry;
      out.push(merged);
      i++;
      continue;
    }
    // `>|file` is bash's noclobber-override redirect. shell-quote splits
    // It into `{op:">"}, {op:"|"}` — the `|` then trips segment splitting
    // And the redirect target is lost. Re-merge to a single `>` op (the
    // Noclobber bit doesn't matter to rule analysis; what matters is that
    // It's a write redirect to the following target).
    if (getOp(e) === '>' && next !== undefined && getOp(next) === '|') {
      out.push({ op: '>' } as unknown as ParseEntry);
      i++;
      continue;
    }
    out.push(e);
  }
  return out;
};

// Count digit-then-redirect adjacencies in the source string (`2>file`,
// `1>&2`, `2>>log`). The `(?<![\w$])` rejects matches inside identifiers
// Like `foo2>bar`. A trailing `>` or `<` with no whitespace is required —
// `echo 2 >file` keeps `2` as a positional arg.
const countFdPrefixRedirects = (cmd: string): number => {
  const matches = cmd.match(/(?<![\w$])\d+(?=[<>])/g);
  return matches?.length ?? 0;
};

const heredocDelimiterFromLine = (line: string): string | null => {
  const match =
    /<<-?\s*(?:"(?<quoted>[^"]+)"|'(?<single>[^']+)'|(?<unquoted>[A-Za-z_][A-Za-z0-9_]*))/u.exec(
      line,
    );
  return (
    match?.groups?.['quoted'] ?? match?.groups?.['single'] ?? match?.groups?.['unquoted'] ?? null
  );
};

const SHELL_STDIN_HEAD_RE =
  /(?:^|[|;&]\s*)(?:\/(?:usr\/bin|bin|usr\/local\/bin|opt\/homebrew\/bin)\/)?(?:sh|bash|zsh|dash|ksh|ash)(?:\s|$)/u;

const heredocFeedsShell = (line: string): boolean => SHELL_STDIN_HEAD_RE.test(line);

const maskLiteralHeredocBodies = (cmd: string): string => {
  const lines = cmd.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    out.push(line);
    const delimiter = heredocDelimiterFromLine(line);
    if (delimiter === null || heredocFeedsShell(line)) {
      continue;
    }
    i++;
    while (i < lines.length && lines[i]!.trim() !== delimiter) {
      i++;
    }
    if (i < lines.length) {
      out.push('__HEREDOC_BODY__');
      out.push(lines[i]!);
    }
  }
  return out.join('\n');
};

// Side-channel for static-string lookup. Mask-protected rules (hasBypass,
// Bash-deny scanning) must never see heredoc body characters — a body
// Containing `# tripwire-allow` or `rm -rf /` would slip past them.
// `unwrapStaticString` still needs the original body of `$(cat <<EOF ... EOF)`
// To validate the wrapped commit message. Keep masking universal, and pass
// The original-body lookup through a separate channel only the static-string
// Extractor consults.
const collectHeredocBodies = (cmd: string): ReadonlyMap<string, string> => {
  const map = new Map<string, string>();
  const lines = cmd.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const delimiter = heredocDelimiterFromLine(line);
    if (delimiter === null || heredocFeedsShell(line)) {
      continue;
    }
    const body: string[] = [];
    i++;
    while (i < lines.length && lines[i]!.trim() !== delimiter) {
      body.push(lines[i]!);
      i++;
    }
    if (!map.has(delimiter)) {
      map.set(delimiter, body.join('\n'));
    }
  }
  return map;
};

const extractShellHeredocCommands = (cmd: string): string[] => {
  const lines = cmd.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const delimiter = heredocDelimiterFromLine(line);
    if (delimiter === null || !heredocFeedsShell(line)) {
      continue;
    }
    const body: string[] = [];
    i++;
    while (i < lines.length && lines[i]!.trim() !== delimiter) {
      body.push(lines[i]!);
      i++;
    }
    if (body.length > 0) {
      out.push(body.join('\n'));
    }
  }
  return out;
};

// Extract inner commands from `$(...)`, `<(...)`, `>(...)`, and `` `...` ``.
// Shell-quote collapses these into opaque sentinel tokens (which is correct
// For safe-path checks — substituted output is unknown), but it also hides
// The inner commands themselves from rule analysis. So `tee >(rm -rf /etc)`
// Would let the `rm` slip through. We pull the inner commands out and
// Analyze them as additional segments.
//
// Backticks don't nest (bash needs `\` escaping for that, which we treat as
// A literal). Process/command substitutions can nest arbitrarily — a depth
// Counter handles the balanced parens.
const findBacktickEnd = (cmd: string, start: number): number | null => {
  for (let i = start; i < cmd.length; i++) {
    const ch = cmd[i]!;
    if (ch === '\\') {
      i++;
      continue;
    }
    if (ch === '`') {
      return i;
    }
  }
  return null;
};

const findSubstitutionEnd = (cmd: string, start: number): number | null => {
  let depth = 1;
  let quote: 'single' | 'double' | null = null;
  for (let j = start; j < cmd.length; j++) {
    const cj = cmd[j]!;
    if (cj === '\\') {
      j++;
      continue;
    }
    if (quote === 'single') {
      if (cj === "'") {
        quote = null;
      }
      continue;
    }
    if (cj === "'") {
      quote ??= 'single';
      continue;
    }
    if (cj === '"') {
      quote = quote === 'double' ? null : 'double';
      continue;
    }
    if (cj === '(') {
      depth++;
      continue;
    }
    if (cj === ')') {
      depth--;
      if (depth === 0) {
        return j;
      }
    }
  }
  return null;
};

const extractInnerCommands = (cmd: string): string[] => {
  const inner: string[] = [];
  let quote: 'single' | 'double' | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]!;
    if (ch === '\\') {
      i++;
      continue;
    }
    if (quote === 'single') {
      if (ch === "'") {
        quote = null;
      }
      continue;
    }
    if (ch === "'") {
      quote ??= 'single';
      continue;
    }
    if (ch === '"') {
      quote = quote === 'double' ? null : 'double';
      continue;
    }
    if (ch === '`') {
      const end = findBacktickEnd(cmd, i + 1);
      if (end !== null) {
        inner.push(cmd.slice(i + 1, end));
        i = end;
      }
      continue;
    }
    const next = cmd[i + 1];
    const isCommandSubStart = ch === '$' && next === '(';
    const isProcessSubStart = quote === null && (ch === '<' || ch === '>') && next === '(';
    if (!isCommandSubStart && !isProcessSubStart) {
      continue;
    }
    const end = findSubstitutionEnd(cmd, i + 2);
    if (end !== null) {
      inner.push(cmd.slice(i + 2, end));
      i = end;
    }
  }
  return inner;
};

// ── Exec-flag extraction (fd -x, find -exec, etc.) ───────────────────
// Tools that take a subcommand on the same arg vector hide that
// Subcommand from rule analysis. Pull it out, substitute the user-
// Provided search root into the placeholder(s), and feed the
// Reconstructed command back through parseCommand so every existing
// Bash rule (deny / scoped-rm / redirect / etc.) sees it.

const HOME_VAR_RE = /^\$\{?HOME\}?(?:\/|$)/;

const pathLikeToken = (t: string): boolean => {
  if (t === '' || t === '-') {
    return false;
  }
  if (t === '/' || t === '~' || t === '.' || t === '..') {
    return true;
  }
  if (
    t.startsWith('/') ||
    t.startsWith('~') ||
    t.startsWith('./') ||
    t.startsWith('../') ||
    HOME_VAR_RE.test(t)
  ) {
    return true;
  }
  return false;
};

// Rank candidate search roots by how dangerous a `cmd <root>` invocation
// Would be. Higher wins.
const pathDangerScore = (t: string): number => {
  if (t === '/') {
    return 100;
  }
  if (t === '~' || HOME_VAR_RE.test(t)) {
    return 90;
  }
  if (/^\/(?<dir>etc|usr|bin|sbin|System|Library|var|boot|root|home)(?<suffix>\/|$)/.test(t)) {
    return 80;
  }
  if (t.startsWith('/Users/')) {
    return 70;
  }
  if (t.startsWith('/') || t.startsWith('~')) {
    return 60;
  }
  if (t.startsWith('../')) {
    return 40;
  }
  if (t === '..' || t === '.' || t.startsWith('./')) {
    return 10;
  }
  return 50;
};

interface ExecSpec {
  // Flag tokens that introduce a nested command, e.g. `-x` / `-exec`.
  readonly execFlags: ReadonlySet<string>;
  // Placeholder tokens the tool substitutes with each match path.
  readonly placeholders: ReadonlySet<string>;
  // Walk tokens[1..execFlagIdx) and return the most-suspicious search root
  // The tool would feed into placeholders, or `.` if nothing path-shaped
  // Is present.
  readonly pickRoot: (tokens: readonly string[], execFlagIdx: number) => string;
}

// Fd's flag layout: flags can appear before or after the pattern/path
// Positionals, and some flags consume a value (-e ts, -t f, -d 3). We
// Need to skip those value tokens, otherwise `ts` is misread as a path.
const FD_VALUE_FLAGS: ReadonlySet<string> = new Set([
  '-e',
  '--extension',
  '-t',
  '--type',
  '-E',
  '--exclude',
  '-d',
  '--max-depth',
  '--min-depth',
  '--exact-depth',
  '-c',
  '--color',
  '--changed-within',
  '--changed-before',
  '-S',
  '--size',
  '-o',
  '--owner',
  '-j',
  '--threads',
  '-g',
  '--glob',
  '--format',
  '--max-results',
  '--ignore-file',
  '--search-path',
  '--base-directory',
  '--path-separator',
  '--and',
]);

const pickFdSearchRoot = (tokens: readonly string[], execFlagIdx: number): string => {
  const candidates: string[] = [];
  let i = 1;
  while (i < execFlagIdx) {
    const t = tokens[i]!;
    if (FD_VALUE_FLAGS.has(t)) {
      i += 2;
      continue;
    }
    if (t.startsWith('-')) {
      i++;
      continue;
    }
    if (pathLikeToken(t)) {
      candidates.push(t);
    }
    i++;
  }
  if (candidates.length === 0) {
    return '.';
  }
  candidates.sort((a, b) => pathDangerScore(b) - pathDangerScore(a));
  return candidates[0]!;
};

// Find's grammar: PATHs come first, before any flag-shaped token. Once we
// Hit a `-`-prefixed token (a test predicate or action), no more paths.
// `find` defaults to cwd if no path is given. We collect everything
// Path-shaped in the prefix region as candidates.
const pickFindSearchRoot = (tokens: readonly string[], execFlagIdx: number): string => {
  const candidates: string[] = [];
  for (let i = 1; i < execFlagIdx; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      break;
    }
    if (pathLikeToken(t)) {
      candidates.push(t);
    }
  }
  if (candidates.length === 0) {
    return '.';
  }
  candidates.sort((a, b) => pathDangerScore(b) - pathDangerScore(a));
  return candidates[0]!;
};

const FD_SPEC: ExecSpec = {
  execFlags: new Set(['-x', '-X', '--exec', '--exec-batch']),
  placeholders: new Set(['{}', '{/}', '{//}', '{.}', '{/.}']),
  pickRoot: pickFdSearchRoot,
};

const FIND_SPEC: ExecSpec = {
  // `-ok` / `-okdir` prompt interactively per-match, but the executed
  // Command is still constructed from agent-controlled input, so treat
  // It the same as `-exec`.
  execFlags: new Set(['-exec', '-execdir', '-ok', '-okdir']),
  placeholders: new Set(['{}']),
  pickRoot: pickFindSearchRoot,
};

const EXEC_SPECS: Readonly<Record<string, ExecSpec>> = Object.assign(
  Object.create(null) as Record<string, ExecSpec>,
  { fd: FD_SPEC, fdfind: FD_SPEC, find: FIND_SPEC, gfind: FIND_SPEC },
);

const substitutePlaceholders = (
  tokens: readonly string[],
  spec: ExecSpec,
  root: string,
): string[] => tokens.map((t) => (spec.placeholders.has(t) ? root : t));

const extractExecCommands = (seg: Segment): string[] => {
  const spec = EXEC_SPECS[seg.head];
  if (spec === undefined) {
    return [];
  }
  const out: string[] = [];
  const tokens = seg.tokens;
  for (let i = 1; i < tokens.length; i++) {
    if (!spec.execFlags.has(tokens[i]!)) {
      continue;
    }
    // Collect tokens until the exec terminator (`;` or `+`, both shared
    // By fd and find) or end of segment. shell-quote turns `\;` into the
    // Literal string token `;`.
    const inner: string[] = [];
    let j = i + 1;
    while (j < tokens.length) {
      const t = tokens[j]!;
      if (t === ';' || t === '+') {
        break;
      }
      inner.push(t);
      j++;
    }
    if (inner.length === 0) {
      continue;
    }
    const head = inner[0]!;
    if (spec.placeholders.has(head)) {
      continue;
    }
    const root = spec.pickRoot(tokens, i);
    out.push(substitutePlaceholders(inner, spec, root).join(' '));
    i = j;
  }
  return out;
};

// ── Substitution unwrappers ──────────────────────────────────────────
//
// Bash hides agent-controlled content inside command substitutions and
// Shell wrappers two different ways, and rules need two different shapes
// Of unwrap:
//
//   1. `sh -c '<script>'` and `bash -c '<script>'` carry a script the
//      Outer parser can't see into. Extracted with
//      `extractShellWrappedCommands(seg)` and re-parsed as bash segments
//      So every existing rule applies. Used by `parseCommand`.
//
//   2. `$(cat <<'TAG' ... TAG)` and `$(echo '...')` / `$(printf '...')`
//      Compute a static string value at runtime. Rules that inspect arg
//      Values (commit-message convention, redirect targets, etc.) need
//      The string, not a re-parse. `unwrapStaticString(token)` returns
//      It; pass-through if the token isn't a recognised substitution.
//
// Both layers cover the same underlying gap — the shell-quote parser
// Treats substitutions as opaque sentinels — and any rule that touches
// Agent-controlled content should route through one of them.

const HEREDOC_SUBST_RE =
  /\$\(\s*cat\s+<<-?\s*['"]?(?<delimiter>\w+)['"]?\s*\n(?<body>[\s\S]*?)\n\s*\k<delimiter>\s*\)/u;
const ECHO_PRINTF_SUBST_RE = /\$\(\s*(?:printf|echo)\s+(?:-[a-zA-Z]+\s+)*'(?<content>[^']*)'/u;

const unwrapStaticString = (value: string, heredocBodies?: ReadonlyMap<string, string>): string => {
  const heredoc = HEREDOC_SUBST_RE.exec(value);
  if (heredoc !== null) {
    const captured = heredoc.groups?.['body'] ?? value;
    if (heredocBodies !== undefined && captured.trim() === '__HEREDOC_BODY__') {
      const delimiter = heredoc.groups?.['delimiter'];
      const real = delimiter === undefined ? undefined : heredocBodies.get(delimiter);
      if (real !== undefined) {
        return real;
      }
    }
    return captured;
  }
  const printf = ECHO_PRINTF_SUBST_RE.exec(value);
  if (printf !== null) {
    return printf.groups?.['content'] ?? value;
  }
  return value;
};

// Recover commands hidden inside a `sh -c '...'` / `bash -c '...'` wrapper.
// Without this, every redirect / deny / scoped-rm rule can be trivially
// Bypassed by wrapping the offending command in `sh -c`. The shell parser
// Otherwise sees `sh` as the head and the script as an opaque positional
// Arg. We pull the script out and feed it back through `parseCommand` so
// All existing rules apply.
const SHELL_WRAPPER_HEADS: ReadonlySet<string> = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'ash',
  '/bin/sh',
  '/bin/bash',
  '/bin/zsh',
  '/bin/dash',
  '/bin/ksh',
  '/usr/bin/sh',
  '/usr/bin/bash',
  '/usr/bin/zsh',
  '/usr/local/bin/bash',
  '/opt/homebrew/bin/bash',
]);

const extractShellWrappedCommands = (seg: Segment): string[] => {
  if (!SHELL_WRAPPER_HEADS.has(seg.head)) {
    return [];
  }
  const tokens = seg.tokens;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t === '-c' && i + 1 < tokens.length) {
      return [tokens[i + 1]!];
    }
    // Combined short flags that include `c`: `-ec`, `-xc`, `-eu c` won't —
    // Only treat `c` as the last char so the next token is the script.
    if (
      t.startsWith('-') &&
      !t.startsWith('--') &&
      t.endsWith('c') &&
      t.length > 2 &&
      i + 1 < tokens.length
    ) {
      return [tokens[i + 1]!];
    }
  }
  return [];
};

// Heads that take `[flags] <command> [args]` on the same arg vector: the
// First non-flag token after the prefix is the real command. `sudo`/`doas`
// (privilege escalation), `xargs` (stdin-driven exec), and `watch` (repeated
// Exec) all hide a sibling command this way, so the same unwrap that handles
// `command`/`env`/`nohup` applies. `sudo` is also matched by bash-deny's
// `ask` rule on the outer segment — both fire, and the more-restrictive
// Interior decision (e.g. `sudo rm -rf /` → deny) wins on merge.
const HEAD_RENAMING_HEADS: ReadonlySet<string> = new Set([
  'command',
  'exec',
  'env',
  'time',
  'nohup',
  'setsid',
  'nice',
  'ionice',
  'chronic',
  'stdbuf',
  'unbuffer',
  'script',
  'taskset',
  'sudo',
  'doas',
  'xargs',
  'watch',
]);

const HEAD_RENAMING_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  command: new Set(),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string', '--block-signal']),
  time: new Set(['-f', '--format', '-o', '--output']),
  nice: new Set(['-n', '--adjustment']),
  ionice: new Set(['-c', '--class', '-n', '--classdata', '-p', '--pid']),
  stdbuf: new Set(['-i', '--input', '-o', '--output', '-e', '--error']),
  script: new Set(['-c', '--command']),
  taskset: new Set(),
  sudo: new Set([
    '-u',
    '--user',
    '-g',
    '--group',
    '-C',
    '--close-from',
    '-D',
    '--chdir',
    '-h',
    '--host',
    '-p',
    '--prompt',
    '-r',
    '--role',
    '-t',
    '--type',
    '-U',
    '--other-user',
    '-R',
    '--chroot',
    '-T',
    '--command-timeout',
  ]),
  doas: new Set(['-a', '-C', '-u']),
  xargs: new Set([
    '-I',
    '-i',
    '-J',
    '-n',
    '--max-args',
    '-P',
    '--max-procs',
    '-s',
    '--max-chars',
    '-L',
    '--max-lines',
    '-E',
    '--eof',
    '-d',
    '--delimiter',
    '-a',
    '--arg-file',
    '--replace',
  ]),
  watch: new Set(['-n', '--interval']),
};

const tokenLooksLikeEnvAssignment = (token: string): boolean =>
  /^[A-Za-z_][A-Za-z0-9_]*=.*/u.test(token);

const skipHeadRenamingPrefix = (tokens: readonly string[]): number => {
  const head = tokens[0]!;
  const valueFlags = HEAD_RENAMING_VALUE_FLAGS[head] ?? new Set<string>();
  let i = 1;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (head === 'env' && tokenLooksLikeEnvAssignment(token)) {
      i++;
      continue;
    }
    if (valueFlags.has(token)) {
      i += 2;
      continue;
    }
    if (token.includes('=') && valueFlags.has(token.slice(0, token.indexOf('=')))) {
      i++;
      continue;
    }
    if (token.startsWith('--') && token !== '--') {
      i++;
      continue;
    }
    if (token.startsWith('-') && token !== '-') {
      i++;
      continue;
    }
    break;
  }
  return i;
};

const extractHeadRenamingCommands = (seg: Segment): string[] => {
  if (!HEAD_RENAMING_HEADS.has(seg.head)) {
    return [];
  }
  if (seg.head === 'script') {
    for (let i = 1; i < seg.tokens.length - 1; i++) {
      const token = seg.tokens[i]!;
      if (token === '-c' || token === '--command') {
        return [seg.tokens[i + 1]!];
      }
      if (token.startsWith('--command=')) {
        return [token.slice('--command='.length)];
      }
    }
  }
  const start = skipHeadRenamingPrefix(seg.tokens);
  const inner = seg.tokens.slice(start).join(' ');
  return inner === '' ? [] : [inner];
};

const EVAL_HEADS: ReadonlySet<string> = new Set(['eval']);

const extractEvalCommands = (seg: Segment): string[] => {
  if (!EVAL_HEADS.has(seg.head)) {
    return [];
  }
  const sub = seg.tokens.slice(1).join(' ');
  return sub === '' ? [] : [sub];
};

// ── rtk (token-optimizing CLI proxy) ─────────────────────────────────
// Rtk wraps real commands so their output is filtered before reaching the
// Agent's context, and Codex auto-prepends it. The wrapper hides the real
// Command from every rule: `rtk proxy rm -rf /` parses with head `rtk` and
// The destructive `rm` buried in opaque positional args. Strip the `rtk`
// Prefix and reconstruct the interior command so the existing rules decide
// On what actually runs.
//
// Grammar: `rtk [global-opts] <subcommand> [args]`. Two subcommand classes
// Exec a sibling command:
//   • wrapper subs — the keyword is dropped, the remainder is an arbitrary
//     Command: `run` (also `-c <string>`), `proxy`, `err`, `test`, `summary`.
//   • tool-proxy subs — the keyword *is* the binary: `git`, `find`, `npm`,
//     `docker`, … Reconstructing from the subcommand onward yields the real
//     Invocation (`git push …`, `find … -delete`). rtk-internal filters that
//     Aren't real binaries (`gain`, `config`, `diff`, …) reconstruct to inert
//     Heads no rule matches, so no allowlist is needed.
const RTK_WRAPPER_SUBCOMMANDS: ReadonlySet<string> = new Set([
  'run',
  'proxy',
  'err',
  'test',
  'summary',
]);

const isRtkHead = (head: string): boolean => head === 'rtk' || head.endsWith('/rtk');

const skipRtkGlobalFlags = (tokens: readonly string[]): number => {
  // Rtk's global options (`-v`/`-vv`/`--verbose`, `--ultra-compact`,
  // `--skip-env`) are all boolean, so any leading flag token can be skipped.
  let i = 1;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (t.startsWith('-') && t !== '-' && t !== '--') {
      i++;
      continue;
    }
    break;
  }
  return i;
};

const dashCommandArg = (tokens: readonly string[], start: number): string | null => {
  for (let k = start; k < tokens.length; k++) {
    const t = tokens[k]!;
    if ((t === '-c' || t === '--command') && k + 1 < tokens.length) {
      return tokens[k + 1]!;
    }
    if (t.startsWith('--command=')) {
      return t.slice('--command='.length);
    }
  }
  return null;
};

const extractRtkCommands = (seg: Segment): string[] => {
  if (!isRtkHead(seg.head)) {
    return [];
  }
  const subIdx = skipRtkGlobalFlags(seg.tokens);
  const sub = seg.tokens[subIdx];
  if (sub === undefined) {
    return [];
  }
  if (RTK_WRAPPER_SUBCOMMANDS.has(sub)) {
    // `rtk run -c '<cmd>'` carries the command in a flag value.
    const viaFlag = dashCommandArg(seg.tokens, subIdx + 1);
    if (viaFlag !== null) {
      return viaFlag === '' ? [] : [viaFlag];
    }
    // Otherwise the command is the positional remainder after the keyword,
    // Skipping any wrapper-local boolean flags.
    let j = subIdx + 1;
    while (j < seg.tokens.length) {
      const t = seg.tokens[j]!;
      if (t === '--') {
        j++;
        break;
      }
      if (t.startsWith('-') && t !== '-') {
        j++;
        continue;
      }
      break;
    }
    const inner = seg.tokens.slice(j).join(' ');
    return inner === '' ? [] : [inner];
  }
  // Tool-proxy subcommand: the subcommand token is the real binary name.
  const inner = seg.tokens.slice(subIdx).join(' ');
  return inner === '' ? [] : [inner];
};

// ── poke run wrapper ─────────────────────────────────────────────────
// `poke run [--origin <slug>] '<cmd>'` runs <cmd> through `sh -c`, so the
// Inner command must be re-analyzed like any other exec wrapper. Without
// This, `poke run 'rm -rf ~'` slips past every rule as a benign `poke` call.
// Unlike rtk, poke run takes the command as a single argument (not the
// Positional remainder), so exactly that one token is the inner command.
const isPokeHead = (head: string): boolean => head === 'poke' || head.endsWith('/poke');

const extractPokeRunCommands = (seg: Segment): string[] => {
  if (!isPokeHead(seg.head) || seg.tokens[1] !== 'run') {
    return [];
  }
  let j = 2;
  while (j < seg.tokens.length) {
    const t = seg.tokens[j]!;
    if (t === '--') {
      j++;
      break;
    }
    if (t === '--origin') {
      j += 2;
      continue;
    }
    if (t.startsWith('--') && t.includes('=')) {
      j++;
      continue;
    }
    if (t.startsWith('-') && t !== '-') {
      j++;
      continue;
    }
    break;
  }
  const inner = seg.tokens[j];
  return inner === undefined || inner === '' ? [] : [inner];
};

// ── Positional-prefix wrappers ───────────────────────────────────────
// Heads where the real command follows one or more positional arguments
// The wrapper consumes itself: `timeout <duration> <cmd>`, `chroot <newroot>
// <cmd>`, `flock <lockfile> <cmd>` (or `flock <lockfile> -c '<cmd>'`), and
// `su [user] -c '<cmd>'`. Skip the flag region, drop the wrapper's own
// Positionals, and the remainder is the command.
interface PrefixWrapperSpec {
  readonly valueFlags: ReadonlySet<string>;
  // Positional args the wrapper consumes before the command (duration, newroot…).
  readonly skipPositionals: number;
  // Whether the command can also arrive via `-c <string>` (su, flock).
  readonly dashCommand: boolean;
}

const PREFIX_WRAPPER_SPECS: Readonly<Record<string, PrefixWrapperSpec>> = {
  timeout: {
    valueFlags: new Set(['-s', '--signal', '-k', '--kill-after']),
    skipPositionals: 1,
    dashCommand: false,
  },
  gtimeout: {
    valueFlags: new Set(['-s', '--signal', '-k', '--kill-after']),
    skipPositionals: 1,
    dashCommand: false,
  },
  chroot: {
    valueFlags: new Set(['--userspec', '--groups']),
    skipPositionals: 1,
    dashCommand: false,
  },
  flock: {
    valueFlags: new Set(['-w', '--wait', '--timeout', '-E', '--conflict-exit-code']),
    skipPositionals: 1,
    dashCommand: true,
  },
  su: { valueFlags: new Set(), skipPositionals: 0, dashCommand: true },
};

const extractPrefixWrapperCommands = (seg: Segment): string[] => {
  const spec = PREFIX_WRAPPER_SPECS[seg.head];
  if (spec === undefined) {
    return [];
  }
  if (spec.dashCommand) {
    const viaFlag = dashCommandArg(seg.tokens, 1);
    if (viaFlag !== null) {
      return viaFlag === '' ? [] : [viaFlag];
    }
  }
  let i = 1;
  while (i < seg.tokens.length) {
    const t = seg.tokens[i]!;
    if (spec.valueFlags.has(t)) {
      i += 2;
      continue;
    }
    if (t.includes('=') && spec.valueFlags.has(t.slice(0, t.indexOf('=')))) {
      i++;
      continue;
    }
    if (t === '--') {
      i++;
      break;
    }
    if (t.startsWith('-') && t !== '-') {
      i++;
      continue;
    }
    break;
  }
  i += spec.skipPositionals;
  const inner = seg.tokens.slice(i).join(' ');
  return inner === '' ? [] : [inner];
};

// Each extractor pulls the inner command(s) a wrapper hides on its own arg
// Vector, to be re-parsed as additional segments so every rule sees what
// Actually runs. Order is irrelevant — all results are unioned into `out`.
const SEGMENT_EXTRACTORS: readonly ((seg: Segment) => string[])[] = [
  extractExecCommands,
  extractShellWrappedCommands,
  extractHeadRenamingCommands,
  extractEvalCommands,
  extractRtkCommands,
  extractPokeRunCommands,
  extractPrefixWrapperCommands,
];

const parseCommand = (cmd: string): Segment[] => {
  let entries: ParseEntry[];
  const cmdForParsing = maskLiteralHeredocBodies(cmd);
  try {
    entries = parse(cmdForParsing, PRESERVE_ENV);
  } catch {
    return [];
  }
  entries = mergeAmpRedirects(entries);
  const fdBudget: FdBudget = { remaining: countFdPrefixRedirects(cmdForParsing) };

  const out: Segment[] = [];
  let buf: ParseEntry[] = [];
  for (const e of entries) {
    const op = getOp(e);
    if (op !== null && SEGMENT_OPS.has(op)) {
      const seg = parseSegment(buf, fdBudget);
      if (seg !== null) {
        out.push(seg);
      }
      buf = [];
      continue;
    }
    buf.push(e);
  }
  const seg = parseSegment(buf, fdBudget);
  if (seg !== null) {
    out.push(seg);
  }

  // Recursively analyze any embedded commands as additional segments. The
  // Outer segment's args are already opaque sentinels (safe-path-failing);
  // This catches dangerous inner commands the outer call would otherwise
  // Hide.
  for (const sub of [...extractInnerCommands(cmd), ...extractShellHeredocCommands(cmd)]) {
    for (const innerSeg of parseCommand(sub)) {
      out.push(innerSeg);
    }
  }

  // Tools like `fd -x …` and `find -exec …` carry an inner subcommand
  // On the same arg vector. Without extraction the executed command is
  // Hidden and slips past every rule. Pull it out (with the user's
  // Search root substituted into placeholders) and parse it as its own
  // Segments so bash-deny et al. see it.
  // Snapshot length: we push new segments into `out` from within the
  // Loop, but should only scan the segments that existed pre-extraction
  // To avoid re-processing extracted ones.
  const preExtractLen = out.length;
  for (let k = 0; k < preExtractLen; k++) {
    const seg = out[k]!;
    for (const extract of SEGMENT_EXTRACTORS) {
      for (const sub of extract(seg)) {
        for (const innerSeg of parseCommand(sub)) {
          out.push(innerSeg);
        }
      }
    }
  }

  return out;
};

const stripLeadingDotSlash = (p: string): string => (p.startsWith('./') ? p.slice(2) : p);

const isSafePathTarget = (
  raw: string,
  extraRelative: readonly string[] = [],
  extraAbsolute: readonly string[] = [],
): boolean => {
  if (raw === '') {
    return false;
  }
  const t = stripLeadingDotSlash(raw);
  if (t === '..' || t.startsWith('../') || t.includes('/../')) {
    return false;
  }
  for (const abs of [...SAFE_ABSOLUTE, ...extraAbsolute]) {
    if (t === abs || t.startsWith(`${abs}/`)) {
      return true;
    }
  }
  for (const rel of [...SAFE_RELATIVE, ...extraRelative]) {
    if (t === rel || t.startsWith(`${rel}/`)) {
      return true;
    }
  }
  return false;
};

const safeScopesSummary = (
  extraRelative: readonly string[] = [],
  extraAbsolute: readonly string[] = [],
): string => {
  const groups: Record<string, readonly string[]> = {
    'build outputs': ['dist', 'build', '_build', 'out', 'target'],
    'js framework outputs': [
      '.next',
      '.nuxt',
      '.svelte-kit',
      '.output',
      '.astro',
      '.angular',
      '.vite',
      '.parcel-cache',
      '.turbo',
      '.vercel',
      '.netlify',
      '.fly',
      '.wrangler',
      '.serverless',
    ],
    'tests / coverage': ['coverage', '.nyc_output'],
    caches: ['.cache', '.ruff_cache', '.mypy_cache', '.pytest_cache', '.ty_cache', '.tox'],
    'language / package': [
      '__pycache__',
      '.venv',
      'venv',
      'node_modules',
      '.gradle',
      'DerivedData',
      '.bundle',
      '.cargo-target',
    ],
    'tmp / state': ['tmp', '.tmp', '.state', '/tmp', '/var/tmp', '/var/folders'],
    iac: ['.terraform'],
    'bundler dev': ['.yarn/cache', '.yarn/install-state.gz', '.pnpm-store', '.bun'],
  };
  if (extraRelative.length > 0) {
    groups['custom relative'] = extraRelative;
  }
  if (extraAbsolute.length > 0) {
    groups['custom absolute'] = extraAbsolute;
  }
  return Object.entries(groups)
    .map(([k, v]) => `  ${k}: ${v.join(', ')}`)
    .join('\n');
};

// Mask heredoc bodies before scanning, otherwise a `# tripwire-allow`
// Smuggled inside a heredoc body (e.g. a commit message piped via
// `$(cat <<EOF ... EOF)`) disarms every rule for the surrounding command.
// A legitimate bypass marker sits on the actual command line, which the
// Mask leaves intact.
const hasBypass = (cmd: string): boolean =>
  /(?<prefix>^|\s)#\s*tripwire-allow\b/.test(maskLiteralHeredocBodies(cmd));

export type { Redirect, Segment };
export {
  EXEC_SPECS,
  collectHeredocBodies,
  hasBypass,
  isSafePathTarget,
  parseCommand,
  safeScopesSummary,
  unwrapStaticString,
};
