import { describe, expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { Effect } from 'effect';

import { decide, runRules, runRulesSync } from '../src/dispatch';
import { deny } from '../src/lib/decision';

describe('rule isolation', () => {
  test('a throwing rule allows only itself and later rules still deny', async () => {
    const decision = await Effect.runPromise(
      runRules(
        [
          {
            name: 'throwing-rule',
            fn: () => {
              throw new Error('test defect');
            },
          },
          { name: 'later-deny', fn: () => deny('later-deny', 'denied after defect') },
        ],
        250,
      ),
    );

    expect(decision).toEqual({ kind: 'deny', message: 'denied after defect', rule: 'later-deny' });
  });

  test('the synchronous rule loop isolates a throwing rule', () => {
    const decision = runRulesSync([
      {
        name: 'throwing-rule',
        fn: () => {
          throw new Error('test defect');
        },
      },
      { name: 'later-deny', fn: () => deny('later-deny', 'denied after defect') },
    ]);

    expect(decision.kind).toBe('deny');
    expect(decision.rule).toBe('later-deny');
  });

  test('the production hook emits valid JSON after a deny', async () => {
    const home = await mkdtemp(path.join(tmpdir(), 'tripwire-runtime-'));
    try {
      const proc = Bun.spawnSync(['bun', 'src/dispatch.ts'], {
        env: { ...process.env, HOME: home },
        stdin: new TextEncoder().encode(
          JSON.stringify({
            hook_event_name: 'PreToolUse',
            tool_name: 'powershell',
            tool_input: { command: 'Get-ChildItem' },
          }),
        ),
        stdout: 'pipe',
        stderr: 'pipe',
      });

      expect(proc.exitCode).toBe(0);
      expect(() => JSON.parse(proc.stdout.toString()) as unknown).not.toThrow();
    } finally {
      await rm(home, { force: true, recursive: true });
    }
  });
});

describe('PowerShell handling', () => {
  test('pre-tool calls deny unsupported PowerShell grammar', () => {
    const decision = decide({
      hook_event_name: 'PreToolUse',
      tool_name: 'powershell',
      tool_input: { command: 'Remove-Item -Recurse C:\\' },
    });

    expect(decision.kind).toBe('deny');
    expect(decision.rule).toBe('powershell-unsupported');
    expect(decision.message).toContain('Use the Bash tool');
  });

  test('post-tool calls fail closed when the scanner is missing', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'tripwire-missing-scanner-'));
    const fixture = 'SYNTHETIC_POWERSHELL_OUTPUT';
    try {
      const decision = decide(
        {
          hook_event_name: 'PostToolUse',
          tool_name: 'powershell',
          tool_response: { stdout: fixture },
        },
        {
          secretScanner: {
            executable: path.join(dir, 'betterleaks-not-installed'),
            timeoutMs: 250,
          },
        },
      );

      expect(decision.kind).toBe('deny');
      expect(decision.rule).toBe('secret-scanner-failed');
      expect(decision.message).toContain('missing-executable');
      expect(decision.message).not.toContain(fixture);
    } finally {
      await rm(dir, { force: true, recursive: true });
    }
  });
});
