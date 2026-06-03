import { type Segment, hasBypass, isSafePathTarget, safeScopesSummary } from '../lib/bash';
import type { SafePathsConfig } from '../lib/config';
import { type Decision, allow, deny } from '../lib/decision';

interface Issue {
  readonly kind: 'rm' | 'find -delete';
  readonly targets: readonly string[];
}

const analyzeRm = (seg: Segment, config: SafePathsConfig): readonly string[] => {
  // `rm -- foo` ends flag parsing. Treat -- as flag-like and stop after it.
  let endOfFlags = false;
  const targets: string[] = [];
  for (const t of seg.tokens.slice(1)) {
    if (!endOfFlags && t === '--') {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && t.startsWith('-') && t !== '-') {
      continue;
    }
    targets.push(t);
  }
  const extraRelative = config.relative ?? [];
  const extraAbsolute = config.absolute ?? [];
  return targets.filter((t) => !isSafePathTarget(t, extraRelative, extraAbsolute));
};

const analyzeFindDelete = (seg: Segment, config: SafePathsConfig): readonly string[] | null => {
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

const bashScopedRm = (
  segments: readonly Segment[],
  cmd: string,
  config: SafePathsConfig,
): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-scoped-rm');
  }
  const issues: Issue[] = [];
  for (const seg of segments) {
    if (seg.head === 'rm') {
      const unsafe = analyzeRm(seg, config);
      if (unsafe.length > 0) {
        issues.push({ kind: 'rm', targets: unsafe });
      }
      continue;
    }
    if (seg.head === 'find') {
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
    `Destructive deletion outside known-safe scopes is blocked. Use \`trash\` (macOS Trash, recoverable) or \`rip\` (graveyard at /tmp/graveyard-$USER, recoverable until reboot) instead. Real \`rm\` and \`find -delete\` are allowed only inside ephemeral build / cache / state directories:\n${safeScopesSummary(extraRelative, extraAbsolute)}\n\nFlagged targets:\n${detail}\n\nIf raw \`rm\` is genuinely needed, append \` # tripwire-allow: <reason>\` to the command.`,
  );
};

export { bashScopedRm };
