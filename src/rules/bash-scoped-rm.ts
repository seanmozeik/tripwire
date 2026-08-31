import {
  isSafePathTarget,
  safeScopesSummary,
  type ShellInvocation,
  type ShellProgram,
} from '../lib/bash';
import type { SafePathsConfig } from '../lib/config';
import { type Decision, allow, deny } from '../lib/decision';

interface Issue {
  readonly kind: 'rm' | 'find -delete';
  readonly targets: readonly string[];
}

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
  return targets.filter((t) => !isSafePathTarget(t, extraRelative, extraAbsolute));
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
  return checked.filter((p) => !isSafePathTarget(p, extraRelative, extraAbsolute));
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
