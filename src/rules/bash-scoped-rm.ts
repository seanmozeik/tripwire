import { type Segment, hasBypass, isSafePathTarget, safeScopesSummary } from '../lib/bash.ts';
import { type Decision, allow, deny } from '../lib/decision.ts';

interface Issue {
  readonly kind: 'rm' | 'find -delete';
  readonly targets: readonly string[];
}

const analyzeRm = (seg: Segment): readonly string[] => {
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
  return targets.filter((t) => !isSafePathTarget(t));
};

const analyzeFindDelete = (seg: Segment): readonly string[] | null => {
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
  return checked.filter((p) => !isSafePathTarget(p));
};

const bashScopedRm = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-scoped-rm');
  }
  const issues: Issue[] = [];
  for (const seg of segments) {
    if (seg.head === 'rm') {
      const unsafe = analyzeRm(seg);
      if (unsafe.length > 0) {
        issues.push({ kind: 'rm', targets: unsafe });
      }
      continue;
    }
    if (seg.head === 'find') {
      const unsafe = analyzeFindDelete(seg);
      if (unsafe !== null && unsafe.length > 0) {
        issues.push({ kind: 'find -delete', targets: unsafe });
      }
    }
  }
  if (issues.length === 0) {
    return allow('bash-scoped-rm');
  }
  const detail = issues
    .map((i) => `  • ${i.kind} on: ${i.targets.map((t) => JSON.stringify(t)).join(', ')}`)
    .join('\n');
  return deny(
    'destructive-outside-safe-paths',
    `Destructive deletion outside known-safe scopes is blocked. Use \`trash\` (macOS Trash, recoverable) or \`rip\` (graveyard at ~/.local/share/graveyard, recoverable) instead. Real \`rm\` and \`find -delete\` are allowed only inside ephemeral build / cache / state directories:\n${safeScopesSummary()}\n\nFlagged targets:\n${detail}\n\nIf raw \`rm\` is genuinely needed, append \` # tripwire-allow: <reason>\` to the command.`,
  );
};

export { bashScopedRm };
