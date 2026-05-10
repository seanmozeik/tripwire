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
const extractInnerCommands = (cmd: string): string[] => {
  const inner: string[] = [];
  // Backticks: simple, non-nesting.
  const bt = cmd.match(/`([^`]+)`/g);
  if (bt !== null) {
    for (const m of bt) {
      inner.push(m.slice(1, -1));
    }
  }
  // $( ), <( ), >( ) with balanced parens.
  for (let i = 0; i < cmd.length - 1; i++) {
    const ch = cmd[i]!;
    const next = cmd[i + 1]!;
    const isSubStart = (ch === '$' || ch === '<' || ch === '>') && next === '(';
    if (!isSubStart) {
      continue;
    }
    let depth = 1;
    let j = i + 2;
    while (j < cmd.length && depth > 0) {
      const cj = cmd[j]!;
      if (cj === '(') {
        depth++;
      } else if (cj === ')') {
        depth--;
      }
      if (depth > 0) {
        j++;
      }
    }
    if (depth === 0) {
      inner.push(cmd.slice(i + 2, j));
      i = j;
    }
  }
  return inner;
};

const parseCommand = (cmd: string): Segment[] => {
  let entries: ParseEntry[];
  try {
    entries = parse(cmd, PRESERVE_ENV);
  } catch {
    return [];
  }
  entries = mergeAmpRedirects(entries);
  const fdBudget: FdBudget = { remaining: countFdPrefixRedirects(cmd) };

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
  for (const sub of extractInnerCommands(cmd)) {
    for (const innerSeg of parseCommand(sub)) {
      out.push(innerSeg);
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

const hasBypass = (cmd: string): boolean => /(^|\s)#\s*tripwire-allow\b/.test(cmd);

export type { Redirect, Segment };
export { hasBypass, isSafePathTarget, parseCommand, safeScopesSummary };
