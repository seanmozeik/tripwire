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
  readonly op: '>' | '>>' | '<' | '<<' | '<<<' | '<>' | '>&' | '<&';
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

const REDIRECT_OPS: ReadonlySet<string> = new Set(['>', '>>', '<', '<<', '<<<', '<>', '>&', '<&']);

const SEGMENT_OPS: ReadonlySet<string> = new Set([';', '&&', '||', '|', '&']);

// Type guards over `ParseEntry`.
const isStringToken = (e: ParseEntry): e is string => typeof e === 'string';
const getOp = (e: ParseEntry): string | null => {
  if (typeof e === 'object' && 'op' in e && typeof e.op === 'string') {
    return e.op;
  }
  return null;
};
const isCommentToken = (e: ParseEntry): boolean => typeof e === 'object' && 'comment' in e;

// Convert one entry to a string for our `tokens` array. Operators and
// Command-sub markers become opaque sentinel tokens.
const entryToToken = (e: ParseEntry): string | null => {
  if (isStringToken(e)) {
    return e;
  }
  const op = getOp(e);
  if (op !== null) {
    if (REDIRECT_OPS.has(op) || SEGMENT_OPS.has(op)) {
      return null;
    }
    return `__op_${op}__`;
  }
  if (isCommentToken(e)) {
    return null;
  }
  return '__tripwire_cmd_sub__';
};

const parseSegment = (entries: readonly ParseEntry[]): Segment | null => {
  const tokens: string[] = [];
  const args: string[] = [];
  const flags: string[] = [];
  const redirects: Redirect[] = [];

  let i = 0;
  while (i < entries.length) {
    const e = entries[i]!;
    const op = getOp(e);
    if (op !== null && REDIRECT_OPS.has(op)) {
      const target = entries[i + 1];
      if (target !== undefined && isStringToken(target)) {
        redirects.push({ op: op as Redirect['op'], target });
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    const t = entryToToken(e);
    if (t !== null) {
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

const parseCommand = (cmd: string): Segment[] => {
  let entries: ParseEntry[];
  try {
    entries = parse(cmd, PRESERVE_ENV);
  } catch {
    return [];
  }

  const out: Segment[] = [];
  let buf: ParseEntry[] = [];
  for (const e of entries) {
    const op = getOp(e);
    if (op !== null && SEGMENT_OPS.has(op)) {
      const seg = parseSegment(buf);
      if (seg !== null) {
        out.push(seg);
      }
      buf = [];
      continue;
    }
    buf.push(e);
  }
  const seg = parseSegment(buf);
  if (seg !== null) {
    out.push(seg);
  }
  return out;
};

const stripLeadingDotSlash = (p: string): string => (p.startsWith('./') ? p.slice(2) : p);

const isSafePathTarget = (raw: string): boolean => {
  if (raw === '') {
    return false;
  }
  const t = stripLeadingDotSlash(raw);
  if (t === '..' || t.startsWith('../') || t.includes('/../')) {
    return false;
  }
  for (const abs of SAFE_ABSOLUTE) {
    if (t === abs || t.startsWith(`${abs}/`)) {
      return true;
    }
  }
  for (const rel of SAFE_RELATIVE) {
    if (t === rel || t.startsWith(`${rel}/`)) {
      return true;
    }
  }
  return false;
};

const safeScopesSummary = (): string => {
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
  return Object.entries(groups)
    .map(([k, v]) => `  ${k}: ${v.join(', ')}`)
    .join('\n');
};

const hasBypass = (cmd: string): boolean => /(^|\s)#\s*tripwire-allow\b/.test(cmd);

export type { Redirect, Segment };
export { hasBypass, isSafePathTarget, parseCommand, safeScopesSummary };
