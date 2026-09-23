import path from 'node:path';

import {
  isSafePathTarget,
  safeScopesSummary,
  type ShellInvocation,
  type ShellProgram,
} from '../lib/bash';
import type { SafePathsConfig } from '../lib/config';
import { type Decision, allow, deny } from '../lib/decision';
import { resolveWritePath } from './path-protect';

interface Issue {
  readonly kind: 'rm' | 'find -delete';
  readonly targets: readonly string[];
}

const safeTarget = (
  target: string,
  seg: ShellInvocation,
  relative: readonly string[],
  absolute: readonly string[],
): boolean => {
  if (!path.isAbsolute(target) && seg.cwd === null) {
    return false;
  }
  if (!isSafePathTarget(target, relative, absolute)) {
    return false;
  }
  const cwd = seg.cwd ?? process.cwd();
  const actual = resolveWritePath(path.resolve(cwd, target));
  return isSafePathTarget(
    path.isAbsolute(target) ? actual : path.relative(resolveWritePath(cwd), actual),
    relative,
    absolute,
  );
};

const analyzeRm = (seg: ShellInvocation, config: SafePathsConfig): readonly string[] => {
  // `rm -- foo` ends flag parsing. Treat -- as flag-like and stop after it.
  let endOfFlags = false;
  const targets: string[] = [];
  for (const t of seg.tokens.slice(1)) {
    if (!endOfFlags && t === '--') {
      endOfFlags = true;
    } else if (endOfFlags || !t.startsWith('-') || t === '-') {
      targets.push(t);
    }
  }
  const extraRelative = config.relative ?? [];
  const extraAbsolute = config.absolute ?? [];
  return targets.filter((t) => !safeTarget(t, seg, extraRelative, extraAbsolute));
};

const analyzeFindDelete = (
  seg: ShellInvocation,
  config: SafePathsConfig,
): readonly string[] | null => {
  if (!seg.tokens.includes('-delete')) {
    return null;
  }
  const paths: string[] = [];
  for (const t of seg.tokens.slice(1)) {
    if (t.startsWith('-')) {
      break;
    }
    paths.push(t);
  }
  const checked = paths.length === 0 ? ['.'] : paths;
  const extraRelative = config.relative ?? [];
  const extraAbsolute = config.absolute ?? [];
  return checked.filter((p) => !safeTarget(p, seg, extraRelative, extraAbsolute));
};

const bashScopedRm = (program: ShellProgram, config: SafePathsConfig): Decision => {
  const issues: Issue[] = [];
  for (const seg of program.invocations) {
    if (seg.head === 'rm') {
      const unsafe = analyzeRm(seg, config);
      if (unsafe.length > 0) {
        issues.push({ kind: 'rm', targets: unsafe });
      }
    } else if (seg.head === 'find') {
      const unsafe = analyzeFindDelete(seg, config);
      if (unsafe !== null && unsafe.length > 0) {
        issues.push({ kind: 'find -delete', targets: unsafe });
      }
    }
  }
  if (issues.length === 0) {
    return allow('bash-scoped-rm');
  }
  const extraRelative = config.relative ?? [];
  const extraAbsolute = config.absolute ?? [];
  const detail = issues
    .map((i) => `  • ${i.kind} on: ${i.targets.map((t) => JSON.stringify(t)).join(', ')}`)
    .join('\n');
  return deny(
    'destructive-outside-safe-paths',
    `Destructive deletion outside known-safe scopes is blocked. Use a recoverable deletion tool or limit the target to an ephemeral build, cache, state, or temporary directory:\n${safeScopesSummary(extraRelative, extraAbsolute)}\n\nFlagged targets:\n${detail}\n\nIf raw deletion is genuinely needed, append \` # tripwire-allow: <reason>\` to the command.`,
  );
};

export { bashScopedRm };
