// Secret scanning via the `betterleaks` binary (Zach Rice's gitleaks
// Successor, MIT). We spawn it once per PostToolUse, write the tool
// Output to a temp file, scan the file, parse JSON findings, redact
// Matches in-place, and delete the temp file.
//
// Why subprocess vs. inline regex: betterleaks ships the curated
// 100+-rule pack the gitleaks ecosystem has tuned over years (AWS, GH,
// Stripe, OpenAI, Anthropic, mongo URLs, JWTs, private keys, plus ~70
// Long-tail vendors). We get all of it for one fork+exec, ~250–300ms.
//
// Why a temp file vs. `--pipe`: betterleaks `--pipe` *adds* stdin to its
// Scan but does not replace the directory walk, so it scans the cwd as
// Well. Writing to a tempfile in /tmp and using `--source <file>` is
// Scoped, deterministic, and only ~5ms slower.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
// oxlint-disable-next-line unicorn/import-style
import { join } from 'node:path';

interface BetterleaksFinding {
  readonly RuleID: string;
  readonly Description: string;
  readonly StartLine: number;
  readonly EndLine: number;
  readonly Secret: string;
  readonly Match: string;
}

interface ScanResult {
  readonly hits: readonly { readonly rule: string; readonly count: number }[];
  readonly redacted: string;
}

const BETTERLEAKS_BIN = '/opt/homebrew/bin/betterleaks';

const summarizeHits = (
  findings: readonly BetterleaksFinding[],
): readonly { rule: string; count: number }[] => {
  const counts = new Map<string, number>();
  for (const f of findings) {
    counts.set(f.RuleID, (counts.get(f.RuleID) ?? 0) + 1);
  }
  return [...counts.entries()].map(([rule, count]) => ({ rule, count }));
};

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);

// Replace every found secret in the original input with a tagged redaction.
const redactWith = (input: string, findings: readonly BetterleaksFinding[]): string => {
  let out = input;
  // Sort by length descending so shorter matches that are substrings of
  // Longer ones don't fire first and break the longer match.
  const sorted = [...findings].toSorted((a, b) => b.Secret.length - a.Secret.length);
  for (const f of sorted) {
    if (f.Secret === '') {
      continue;
    }
    out = out.replaceAll(f.Secret, `[REDACTED:${f.RuleID}]`);
  }
  return out;
};

const scanAndRedact = (input: string, timeoutMs = 5000): ScanResult => {
  if (input.length === 0) {
    return { hits: [], redacted: input };
  }
  const dir = mkdtempSync(join(tmpdir(), 'tripwire-scan-'));
  const inPath = join(dir, 'input');
  const reportPath = join(dir, 'report.json');
  try {
    writeFileSync(inPath, input);
    const result = spawnSync(
      BETTERLEAKS_BIN,
      [
        'detect',
        '--no-git',
        '--no-banner',
        '--no-color',
        '--report-format',
        'json',
        '--report-path',
        reportPath,
        '--source',
        inPath,
        '--exit-code',
        '0',
        '--log-level',
        'error',
      ],
      { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 },
    );
    if (result.error !== undefined) {
      return { hits: [], redacted: input };
    }
    let findings: BetterleaksFinding[];
    try {
      const raw = readFileSync(reportPath, 'utf8');
      const parsed = JSON.parse(raw || '[]') as unknown;
      findings = Array.isArray(parsed) ? (parsed as BetterleaksFinding[]) : [];
    } catch {
      return { hits: [], redacted: input };
    }
    if (findings.length === 0) {
      return { hits: [], redacted: input };
    }
    return { hits: summarizeHits(findings), redacted: redactWith(input, findings) };
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
};

// `escapeRegExp` is exported so tests / callers can build patterns over the
// Redacted output without re-implementing escaping.
export type { BetterleaksFinding, ScanResult };
export { escapeRegExp, scanAndRedact };
