// Betterleaks supplies the maintained secret-rule set. The stdin command keeps
// scanned content in memory and writes its JSON report to stdout.

import { spawnSync } from 'node:child_process';

import { Result, Schema } from 'effect';

import type { SecretScannerConfig } from './config';

const BetterleaksFindingSchema = Schema.Struct({
  RuleID: Schema.String,
  Description: Schema.String,
  StartLine: Schema.Finite,
  EndLine: Schema.Finite,
  Secret: Schema.String,
  Match: Schema.String,
});

const BetterleaksReportSchema = Schema.Array(BetterleaksFindingSchema);

type BetterleaksFinding = typeof BetterleaksFindingSchema.Type;

interface ScanSuccess {
  readonly ok: true;
  readonly hits: readonly { readonly rule: string; readonly count: number }[];
  readonly redacted: string;
}

type ScanFailureCategory = 'missing-executable' | 'timeout' | 'non-zero-exit' | 'malformed-json';

interface ScanFailure {
  readonly ok: false;
  readonly category: ScanFailureCategory;
}

type ScanResult = ScanSuccess | ScanFailure;

interface ScannerInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly input: string;
  readonly timeoutMs: number;
}

interface ScannerProcessResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly error?: unknown;
}

type ScannerRunner = (invocation: ScannerInvocation) => ScannerProcessResult;

const BETTERLEAKS_ARGS = [
  'stdin',
  '--report-format',
  'json',
  '--report-path',
  '-',
  '--exit-code',
  '0',
  '--no-banner',
  '--no-color',
  '--log-level',
  'error',
] as const;

const defaultScannerRunner: ScannerRunner = ({ executable, args, input, timeoutMs }) => {
  const result = spawnSync(executable, args, {
    encoding: 'utf8',
    input,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'ignore'],
    timeout: timeoutMs,
  });
  const processResult: ScannerProcessResult = {
    status: result.status,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
  };
  return result.error === undefined ? processResult : { ...processResult, error: result.error };
};

const errorCode = (cause: unknown): string | undefined => {
  if (typeof cause !== 'object' || cause === null || !('code' in cause)) {
    return undefined;
  }
  return typeof cause.code === 'string' ? cause.code : undefined;
};

const classifyExecutionFailure = (cause: unknown): ScanFailureCategory => {
  const code = errorCode(cause);
  if (code === 'ENOENT') {
    return 'missing-executable';
  }
  if (code === 'ETIMEDOUT') {
    return 'timeout';
  }
  return 'non-zero-exit';
};

const summarizeHits = (
  findings: readonly BetterleaksFinding[],
): readonly { rule: string; count: number }[] => {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    counts.set(finding.RuleID, (counts.get(finding.RuleID) ?? 0) + 1);
  }
  return [...counts.entries()].map(([rule, count]) => ({ rule, count }));
};

const escapeRegExp = (value: string): string =>
  value.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);

// Replace every found secret in the original input with a tagged redaction.
const redactWith = (input: string, findings: readonly BetterleaksFinding[]): string => {
  let output = input;
  // Sort by length descending so shorter matches that are substrings of
  // Longer ones do not fire first and break the longer match.
  const sorted = [...findings].toSorted((a, b) => b.Secret.length - a.Secret.length);
  for (const finding of sorted) {
    if (finding.Secret === '') {
      continue;
    }
    output = output.replaceAll(finding.Secret, `[REDACTED:${finding.RuleID}]`);
  }
  return output;
};

const scanAndRedact = (
  input: string,
  config: SecretScannerConfig,
  runner: ScannerRunner = defaultScannerRunner,
): ScanResult => {
  if (input.length === 0) {
    return { ok: true, hits: [], redacted: input };
  }

  let processResult: ScannerProcessResult;
  try {
    processResult = runner({
      executable: config.executable,
      args: BETTERLEAKS_ARGS,
      input,
      timeoutMs: config.timeoutMs,
    });
  } catch {
    return { ok: false, category: 'non-zero-exit' };
  }

  if (processResult.error !== undefined) {
    return { ok: false, category: classifyExecutionFailure(processResult.error) };
  }
  if (processResult.status !== 0) {
    return { ok: false, category: 'non-zero-exit' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(processResult.stdout) as unknown;
  } catch {
    return { ok: false, category: 'malformed-json' };
  }

  const decoded = Schema.decodeUnknownResult(BetterleaksReportSchema)(parsed);
  if (Result.isFailure(decoded)) {
    return { ok: false, category: 'malformed-json' };
  }

  const findings = decoded.success;
  return { ok: true, hits: summarizeHits(findings), redacted: redactWith(input, findings) };
};

// `escapeRegExp` is exported so tests and callers can build patterns over the
// Redacted output without reimplementing escaping.
export type {
  BetterleaksFinding,
  ScanFailure,
  ScanFailureCategory,
  ScannerInvocation,
  ScannerProcessResult,
  ScannerRunner,
  ScanResult,
  ScanSuccess,
};
export { escapeRegExp, scanAndRedact };
