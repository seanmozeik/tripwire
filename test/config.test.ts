// Config loading must fail loud, never silently fall back to defaults when a
// Config file is present but broken. A *missing* file is the one legitimate
// Defaults case. These tests drive a fictional config in a temp dir (no real
// `~/.config` path, no PII) via the `path` seam, plus one end-to-end check that
// The dispatcher emits a `deny` on a broken config.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { Effect } from 'effect';

import { loadConfig, loadConfigResult } from '../src/lib/config';
import type { HookEvent } from '../src/lib/event';

let dir = '';
let configPath = '';

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'tripwire-config-'));
  configPath = path.join(dir, 'config.json');
});

afterEach(async () => {
  await rm(dir, { force: true, recursive: true });
});

describe('loadConfigResult', () => {
  test('missing file → ok with defaults (the one quiet case)', async () => {
    const result = await Effect.runPromise(loadConfigResult(path.join(dir, 'absent.json')));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.config.git?.protectedBranches).toContain('main');
      expect(result.config.blockedCommands).toEqual([]);
    }
  });

  test('valid custom config → ok, merged, custom rule preserved', async () => {
    await writeFile(
      configPath,
      JSON.stringify({
        blockedCommands: [{ pattern: 'example-danger', message: 'use example-safe instead' }],
      }),
    );
    const result = await Effect.runPromise(loadConfigResult(configPath));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.config.blockedCommands).toHaveLength(1);
      expect(result.config.blockedCommands?.[0]?.pattern).toBe('example-danger');
      // Defaults still merged in for the untouched sections.
      expect(result.config.git?.enforceConventionalCommits).toBe(true);
    }
  });

  test('unknown top-level key → ok:false naming the key (the rtk trigger)', async () => {
    await writeFile(configPath, JSON.stringify({ rtk: { foo: 'bar' } }));
    const result = await Effect.runPromise(loadConfigResult(configPath));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rtk');
    }
  });

  test('malformed JSON → ok:false', async () => {
    await writeFile(configPath, '{ not valid json');
    const result = await Effect.runPromise(loadConfigResult(configPath));
    expect(result.ok).toBe(false);
  });
});

describe('loadConfig (loud loader)', () => {
  test('broken config dies rather than silently defaulting', async () => {
    await writeFile(configPath, JSON.stringify({ rtk: {} }));
    let threw = false;
    try {
      await Effect.runPromise(loadConfig(configPath));
    } catch (error) {
      threw = true;
      expect(String(error)).toContain('config load failed');
    }
    expect(threw).toBe(true);
  });

  test('valid config resolves to the merged Config', async () => {
    await writeFile(configPath, JSON.stringify({ allowedCommands: [] }));
    const config = await Effect.runPromise(loadConfig(configPath));
    expect(config.git?.protectedBranches).toContain('main');
  });
});

describe('dispatcher on broken config', () => {
  test('PreToolUse Bash → deny config-error (fail closed)', async () => {
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
    const proc = Bun.spawnSync(['bun', 'src/dispatch.ts'], {
      env: { ...process.env, HOME: home },
      stdin: new TextEncoder().encode(JSON.stringify(event)),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const out = JSON.parse(proc.stdout.toString()) as {
      hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
    };
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput?.permissionDecisionReason).toContain('config-error');

    await rm(home, { force: true, recursive: true });
  });
});
