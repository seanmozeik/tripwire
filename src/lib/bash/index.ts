// Bash is parsed once into an AST-backed security model. Rules inspect the
// Normalized invocations and typed values in ShellProgram. They never reparse
// Quoted text or flatten Bash syntax into an alternate grammar.

import type { ShellProgram } from './types';
import { DYNAMIC_VALUE } from './values';

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

const stripLeadingDotSlash = (path: string): string =>
  path.startsWith('./') ? path.slice(2) : path;

const isSafePathTarget = (
  raw: string,
  extraRelative: readonly string[] = [],
  extraAbsolute: readonly string[] = [],
): boolean => {
  if (raw === '' || raw === DYNAMIC_VALUE) {
    return false;
  }
  const target = stripLeadingDotSlash(raw);
  if (target === '..' || target.startsWith('../') || target.includes('/../')) {
    return false;
  }
  for (const absolute of [...SAFE_ABSOLUTE, ...extraAbsolute]) {
    if (target === absolute || target.startsWith(`${absolute}/`)) {
      return true;
    }
  }
  for (const relative of [...SAFE_RELATIVE, ...extraRelative]) {
    if (target === relative || target.startsWith(`${relative}/`)) {
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
    'tmp / state': ['tmp', '.tmp', '.state', ...SAFE_ABSOLUTE],
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
    .map(([name, values]) => `  ${name}: ${values.join(', ')}`)
    .join('\n');
};

const hasBypass = (program: ShellProgram): boolean => program.hasBypass;

export type {
  BashAnalysisOptions,
  ExecutionCarrierAlias,
  ExecutionCarrierKind,
  PipelinePosition,
  ShellDiagnostic,
  ShellDiagnosticKind,
  ShellInvocation,
  ShellProgram,
  ShellRedirect,
  ShellWord,
  ShellWordKind,
  SourceRange,
} from './types';
export { analyzeBash } from './analyze';
export { DYNAMIC_VALUE } from './values';
export { hasBypass, isSafePathTarget, safeScopesSummary };
