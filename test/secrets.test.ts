import * as bunTest from 'bun:test';

import { scanAndRedact, type ScannerRunner } from '../src/lib/secrets';
import { postSecretScrub } from '../src/rules/post-secret-scrub';

const scannerConfig = { executable: '/custom/bin/betterleaks', timeoutMs: 1250 } as const;

const finding = (rule: string, secret: string) => ({
  RuleID: rule,
  Description: 'Synthetic test rule',
  StartLine: 1,
  EndLine: 1,
  Secret: secret,
  Match: secret,
});

const reportRunner =
  (report: unknown): ScannerRunner =>
  () => ({ status: 0, stdout: JSON.stringify(report) });

bunTest.describe('scanAndRedact', () => {
  bunTest.test('uses stdin mode and passes the configured executable and timeout', () => {
    const fixture = 'SYNTHETIC_SCANNER_INPUT';
    let invocation: Parameters<ScannerRunner>[0] | undefined;
    const runner: ScannerRunner = (value) => {
      invocation = value;
      return { status: 0, stdout: '[]' };
    };

    bunTest
      .expect(scanAndRedact(fixture, scannerConfig, runner))
      .toEqual({ ok: true, hits: [], redacted: fixture });
    bunTest
      .expect(invocation)
      .toEqual({
        executable: scannerConfig.executable,
        args: [
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
        ],
        input: fixture,
        timeoutMs: scannerConfig.timeoutMs,
      });
  });

  bunTest.test('preserves exact redaction behavior for overlapping findings', () => {
    const short = 'SYNTHETIC_SECRET';
    const long = 'SYNTHETIC_SECRET_LONG';
    const input = `${long} / ${short} / ${long}`;

    const result = scanAndRedact(
      input,
      scannerConfig,
      reportRunner([finding('short-rule', short), finding('long-rule', long)]),
    );

    bunTest.expect(result).toEqual({
      ok: true,
      hits: [
        { rule: 'short-rule', count: 1 },
        { rule: 'long-rule', count: 1 },
      ],
      redacted: '[REDACTED:long-rule] / [REDACTED:short-rule] / [REDACTED:long-rule]',
    });
  });

  bunTest.test('returns an exact no-hit result', () => {
    const fixture = 'SYNTHETIC_NO_HIT_INPUT';
    bunTest
      .expect(scanAndRedact(fixture, scannerConfig, reportRunner([])))
      .toEqual({ ok: true, hits: [], redacted: fixture });
  });

  bunTest.test('classifies a missing executable without exposing process details', () => {
    const fixture = 'SYNTHETIC_MISSING_EXECUTABLE_INPUT';
    const error = Object.assign(new Error(`do not expose ${fixture}`), { code: 'ENOENT' });
    const result = scanAndRedact(fixture, scannerConfig, () => ({
      status: null,
      stdout: fixture,
      error,
    }));

    bunTest.expect(result).toEqual({ ok: false, category: 'missing-executable' });
    bunTest.expect(JSON.stringify(result)).not.toContain(fixture);
  });

  bunTest.test('classifies a timeout without exposing process details', () => {
    const fixture = 'SYNTHETIC_TIMEOUT_INPUT';
    const error = Object.assign(new Error(`do not expose ${fixture}`), { code: 'ETIMEDOUT' });
    const result = scanAndRedact(fixture, scannerConfig, () => ({
      status: null,
      stdout: fixture,
      error,
    }));

    bunTest.expect(result).toEqual({ ok: false, category: 'timeout' });
    bunTest.expect(JSON.stringify(result)).not.toContain(fixture);
  });

  bunTest.test('classifies a non-zero exit without exposing scanner output', () => {
    const fixture = 'SYNTHETIC_NON_ZERO_INPUT';
    const result = scanAndRedact(fixture, scannerConfig, () => ({ status: 2, stdout: fixture }));

    bunTest.expect(result).toEqual({ ok: false, category: 'non-zero-exit' });
    bunTest.expect(JSON.stringify(result)).not.toContain(fixture);
  });

  bunTest.test('classifies invalid JSON without exposing scanner output', () => {
    const fixture = 'SYNTHETIC_INVALID_JSON_INPUT';
    const result = scanAndRedact(fixture, scannerConfig, () => ({
      status: 0,
      stdout: `{${fixture}`,
    }));

    bunTest.expect(result).toEqual({ ok: false, category: 'malformed-json' });
    bunTest.expect(JSON.stringify(result)).not.toContain(fixture);
  });

  bunTest.test('rejects every malformed finding instead of dropping it', () => {
    const result = scanAndRedact(
      'SYNTHETIC_MALFORMED_FINDING_INPUT',
      scannerConfig,
      reportRunner([finding('valid-rule', 'SYNTHETIC_VALUE'), { RuleID: 'incomplete' }]),
    );

    bunTest.expect(result).toEqual({ ok: false, category: 'malformed-json' });
  });
});

bunTest.describe('postSecretScrub', () => {
  bunTest.test('blocks scanner failure without exposing the source output', () => {
    const fixture = 'SYNTHETIC_POST_FAILURE_INPUT';
    const decision = postSecretScrub({
      toolName: 'Bash',
      response: { stdout: fixture },
      secretScanner: scannerConfig,
      scannerRunner: () => ({ status: null, stdout: fixture, error: { code: 'ENOENT' } }),
    });

    bunTest.expect(decision.kind).toBe('deny');
    bunTest.expect(decision.rule).toBe('secret-scanner-failed');
    bunTest.expect(decision.message).toContain('Betterleaks 1.5.0');
    bunTest.expect(decision.message).not.toContain(fixture);
  });

  bunTest.test('blocks malformed scanner output without exposing the source output', () => {
    const fixture = 'SYNTHETIC_POST_MALFORMED_INPUT';
    const decision = postSecretScrub({
      toolName: 'Bash',
      response: { stdout: fixture },
      secretScanner: scannerConfig,
      scannerRunner: () => ({ status: 0, stdout: `{${fixture}` }),
    });

    bunTest.expect(decision.kind).toBe('deny');
    bunTest.expect(decision.rule).toBe('secret-scanner-failed');
    bunTest.expect(decision.message).not.toContain(fixture);
  });

  bunTest.test('blocks a finding with only the exact redacted output', () => {
    const secret = 'SYNTHETIC_POST_SECRET';
    const decision = postSecretScrub({
      toolName: 'Bash',
      response: { stdout: `value=${secret}` },
      secretScanner: scannerConfig,
      scannerRunner: reportRunner([finding('synthetic-rule', secret)]),
    });

    bunTest.expect(decision.kind).toBe('deny');
    bunTest.expect(decision.rule).toBe('secrets-in-output');
    bunTest.expect(decision.message).toContain('value=[REDACTED:synthetic-rule]');
    bunTest.expect(decision.message).not.toContain(secret);
  });
});
