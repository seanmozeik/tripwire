// Config loading must fail loud, never silently fall back to defaults when a
// Config file is present but broken. A *missing* file is the one legitimate
// Defaults case. These tests drive a fictional config in a temp dir (no real
// `~/.config` path, no PII) via the `path` seam, plus one end-to-end check that
// The dispatcher emits a `deny` on a broken config.

import * as bunTest from 'bun:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { Effect } from 'effect';

import { decide } from '../src';
import { loadConfig, loadConfigResult } from '../src/lib/config';
import type { HookEvent } from '../src/lib/event';
import { parseJsonRecord, recordField } from './support/json';

let dir = '';
let configPath = '';

bunTest.beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'tripwire-config-'));
  configPath = path.join(dir, 'config.json');
});

bunTest.afterEach(async () => {
  await rm(dir, { force: true, recursive: true });
});

bunTest.describe('loadConfigResult', () => {
  bunTest.test('missing file → ok with defaults (the one quiet case)', async () => {
    const result = await Effect.runPromise(loadConfigResult(path.join(dir, 'absent.json')));
    bunTest.expect(result.ok).toBe(true);
    if (result.ok) {
      bunTest.expect(result.config.git.protectedBranches).toEqual([]);
      bunTest.expect(result.config.git.enforceConventionalCommits).toBe(false);
      bunTest.expect(result.config.toolPolicies).toEqual([]);
      bunTest.expect(result.config.blockedCommands).toEqual([]);
      bunTest.expect(result.config.ruleActions).toEqual({});
      bunTest.expect(result.config.shell.executionCarrierAliases).toEqual([]);
      bunTest
        .expect(result.config.secretScanner)
        .toEqual({ executable: 'betterleaks', timeoutMs: 5000 });
    }
  });

  bunTest.test('valid custom config → ok, merged, custom rule preserved', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        blockedCommands: [{ pattern: 'example-danger', message: 'use example-safe instead' }],
      }),
    );
    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(true);
    if (result.ok) {
      bunTest.expect(result.config.blockedCommands).toHaveLength(1);
      bunTest.expect(result.config.blockedCommands[0]?.pattern).toBe('example-danger');
      // Defaults still merged in for the untouched sections.
      bunTest.expect(result.config.git.enforceConventionalCommits).toBe(false);
    }
  });

  bunTest.test('loads typed tool policies and deep-merges partial Git policy', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        git: { enforceConventionalCommits: true },
        toolPolicies: [
          {
            rule: 'prefer-example',
            executables: ['legacy-example'],
            action: 'warn',
            message: 'Use example instead.',
            match: { argumentsStartWith: ['scan'], shortFlagsIncludeAll: ['r'] },
          },
        ],
      }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(true);
    if (result.ok) {
      bunTest
        .expect(result.config.git)
        .toEqual({ protectedBranches: [], enforceConventionalCommits: true });
      bunTest.expect(result.config.toolPolicies[0]?.rule).toBe('prefer-example');
    }
  });

  bunTest.test('loads typed secret scanner configuration', async () => {
    await writeFile(
      configPath,
      JSON.stringify({ secretScanner: { executable: '/custom/bin/betterleaks', timeoutMs: 1250 } }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(true);
    if (result.ok) {
      bunTest
        .expect(result.config.secretScanner)
        .toEqual({ executable: '/custom/bin/betterleaks', timeoutMs: 1250 });
    }
  });

  bunTest.test('loads typed shell execution-carrier aliases', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        shell: {
          executionCarrierAliases: [{ command: ['just', 'tailnet', 'ssh'], equivalentTo: 'ssh' }],
        },
      }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(true);
    if (result.ok) {
      bunTest
        .expect(result.config.shell.executionCarrierAliases)
        .toEqual([{ command: ['just', 'tailnet', 'ssh'], equivalentTo: 'ssh' }]);
    }
  });

  bunTest.test('loads typed workflow-policy rule actions', async () => {
    await writeFile(
      configPath,
      JSON.stringify({ ruleActions: { 'no-verify': 'ask', sudo: 'warn' } }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(true);
    if (result.ok) {
      bunTest.expect(result.config.ruleActions).toEqual({ 'no-verify': 'ask', sudo: 'warn' });
    }
  });

  bunTest.test('rejects unknown and safety-invariant rule action keys', async () => {
    for (const rule of ['no-verfiy', 'rm-rf-root']) {
      await writeFile(configPath, JSON.stringify({ ruleActions: { [rule]: 'allow' } }));
      const result = await Effect.runPromise(loadConfigResult(configPath));
      bunTest.expect(result.ok).toBe(false);
      if (!result.ok) {
        bunTest.expect(result.error).toContain(rule);
      }
    }
  });

  bunTest.test('rejects empty shell execution-carrier commands', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        shell: { executionCarrierAliases: [{ command: [], equivalentTo: 'ssh' }] },
      }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(false);
  });

  bunTest.test('rejects non-positive scanner timeout', async () => {
    await writeFile(
      configPath,
      JSON.stringify({ secretScanner: { executable: 'betterleaks', timeoutMs: 0 } }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(false);
    if (!result.ok) {
      bunTest.expect(result.error).toContain('timeoutMs');
    }
  });

  bunTest.test('rejects unknown scanner fields', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        secretScanner: { executable: 'betterleaks', timeoutMs: 5000, extra: true },
      }),
    );

    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(false);
    if (!result.ok) {
      bunTest.expect(result.error).toContain('extra');
    }
  });

  bunTest.test('applies a tool policy through the file loader and dispatcher', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        toolPolicies: [
          {
            rule: 'prefer-example',
            executables: ['legacy-example'],
            action: 'warn',
            message: 'Use example instead.',
          },
        ],
      }),
    );

    const config = await Effect.runPromise(loadConfig(configPath));
    const decision = decide(
      {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'legacy-example scan' },
      },
      config,
    );
    bunTest.expect(decision).toMatchObject({ kind: 'warn', rule: 'prefer-example' });
  });

  bunTest.test('unknown top-level key → ok:false naming the key (the rtk trigger)', async () => {
    await writeFile(configPath, JSON.stringify({ rtk: { foo: 'bar' } }));
    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(false);
    if (!result.ok) {
      bunTest.expect(result.error).toContain('rtk');
    }
  });

  bunTest.test('malformed JSON → ok:false', async () => {
    await writeFile(configPath, '{ not valid json');
    const result = await Effect.runPromise(loadConfigResult(configPath));
    bunTest.expect(result.ok).toBe(false);
  });

  bunTest.test('non-ENOENT read failure → ok:false', async () => {
    const parentFile = path.join(dir, 'not-a-directory');
    await writeFile(parentFile, 'file');

    const result = await Effect.runPromise(loadConfigResult(path.join(parentFile, 'config.json')));

    bunTest.expect(result.ok).toBe(false);
    if (!result.ok) {
      bunTest.expect(result.error).toContain('ConfigReadError');
      bunTest.expect(result.error).toContain('ENOTDIR');
    }
  });
});

bunTest.describe('loadConfig (loud loader)', () => {
  bunTest.test('broken config dies rather than silently defaulting', async () => {
    await writeFile(configPath, JSON.stringify({ rtk: {} }));
    let threw = false;
    try {
      await Effect.runPromise(loadConfig(configPath));
    } catch (error) {
      threw = true;
      bunTest.expect(String(error)).toContain('config load failed');
    }
    bunTest.expect(threw).toBe(true);
  });

  bunTest.test('valid config resolves to the merged Config', async () => {
    await writeFile(configPath, JSON.stringify({ allowedCommands: [] }));
    const config = await Effect.runPromise(loadConfig(configPath));
    bunTest.expect(config.git.protectedBranches).toEqual([]);
  });
});

bunTest.describe('dispatcher on broken config', () => {
  bunTest.test('PreToolUse Bash → deny config-error (fail closed)', async () => {
    const home = await mkdtemp(path.join(tmpdir(), 'tripwire-home-'));
    await mkdir(path.join(home, '.config', 'tripwire'), { recursive: true });
    await writeFile(
      path.join(home, '.config', 'tripwire', 'config.json'),
      JSON.stringify({ rtk: {} }),
    );

    const event: HookEvent = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'echo hi' },
    };
    const proc = Bun.spawnSync([process.execPath, 'src/dispatch.ts'], {
      env: { ...process.env, HOME: home },
      stdin: new TextEncoder().encode(JSON.stringify(event)),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const out = parseJsonRecord(proc.stdout.toString());
    const hookOutput = recordField(out, 'hookSpecificOutput');
    bunTest.expect(hookOutput?.['permissionDecision']).toBe('deny');
    bunTest.expect(hookOutput?.['permissionDecisionReason']).toContain('config-error');

    await rm(home, { force: true, recursive: true });
  });

  bunTest.test(
    'PostToolUse still fails closed, then the next PreToolUse denies the config',
    async () => {
      const home = await mkdtemp(path.join(tmpdir(), 'tripwire-home-'));
      await mkdir(path.join(home, '.config', 'tripwire'), { recursive: true });
      await writeFile(
        path.join(home, '.config', 'tripwire', 'config.json'),
        JSON.stringify({ rtk: {} }),
      );

      const run = (event: HookEvent) => {
        const proc = Bun.spawnSync([process.execPath, 'src/dispatch.ts'], {
          env: { ...process.env, HOME: home, PATH: path.join(home, 'empty-path') },
          stdin: new TextEncoder().encode(JSON.stringify(event)),
          stdout: 'pipe',
          stderr: 'pipe',
        });
        bunTest.expect(proc.exitCode).toBe(0);
        return parseJsonRecord(proc.stdout.toString());
      };

      const fixture = 'SYNTHETIC_SCANNER_INPUT';
      const post = run({
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_response: { stdout: fixture },
      });
      bunTest.expect(post['decision']).toBe('block');
      bunTest.expect(post['reason']).toContain('secret-scanner-failed');
      bunTest.expect(post['reason']).not.toContain(fixture);

      const nextPre = run({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo hi' },
      });
      bunTest
        .expect(recordField(nextPre, 'hookSpecificOutput')?.['permissionDecision'])
        .toBe('deny');

      await rm(home, { force: true, recursive: true });
    },
  );
});
