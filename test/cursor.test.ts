import * as bunTest from 'bun:test';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';

import { normalizeHookInput } from '../src/lib/cursor';
import { addCursorHook, installCursor, parseCursorConfig } from '../src/lib/install';
import { parseJsonRecord, recordArrayField, recordField } from './support/json';

const runCursorDispatch = (eventName: string, input: unknown): unknown => {
  const processResult = Bun.spawnSync(
    [process.execPath, 'src/dispatch.ts', '--cursor-event', eventName],
    { stdin: new TextEncoder().encode(JSON.stringify(input)), stdout: 'pipe', stderr: 'pipe' },
  );
  bunTest.expect(processResult.exitCode).toBe(0);
  return JSON.parse(processResult.stdout.toString()) as unknown;
};

bunTest.describe('Cursor hook normalization', () => {
  bunTest.test('turns beforeShellExecution into a Tripwire Bash pre-tool event', () => {
    const normalized = normalizeHookInput(
      { command: 'rm -rf /', cwd: '/tmp' },
      'beforeShellExecution',
    );

    bunTest
      .expect(normalized.host)
      .toEqual({ kind: 'cursor', eventName: 'beforeShellExecution', post: false });
    bunTest
      .expect(normalized.event)
      .toMatchObject({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'rm -rf /' },
      });
  });

  bunTest.test('normalizes Cursor Shell tool payloads from generic preToolUse', () => {
    const normalized = normalizeHookInput({
      hook_event_name: 'preToolUse',
      tool_name: 'Shell',
      tool_input: { command: 'printf safe' },
    });

    bunTest
      .expect(normalized.event)
      .toMatchObject({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'printf safe' },
      });
  });

  bunTest.test('infers a top-level generic shell payload when Cursor omits tool metadata', () => {
    const normalized = normalizeHookInput({
      hook_event_name: 'preToolUse',
      command: 'npm --version',
    });

    bunTest
      .expect(normalized.event)
      .toMatchObject({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'npm --version' },
      });
  });

  bunTest.test('maps afterShellExecution output to Tripwire post-tool response', () => {
    const normalized = normalizeHookInput(
      { command: 'printf safe', output: 'safe output' },
      'afterShellExecution',
    );

    bunTest
      .expect(normalized.event)
      .toMatchObject({
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_response: { stdout: 'safe output', stderr: '' },
      });
  });

  bunTest.test('rejects an incomplete known Cursor pre-tool payload', () => {
    bunTest.expect(() => normalizeHookInput({}, 'beforeShellExecution')).toThrow('missing command');
  });
});

bunTest.describe('Cursor hook output', () => {
  bunTest.test('denies a dangerous beforeShellExecution command', () => {
    bunTest
      .expect(runCursorDispatch('beforeShellExecution', { command: 'rm -rf /' }))
      .toMatchObject({ continue: true, permission: 'deny' });
  });

  bunTest.test('allows a safe beforeShellExecution command', () => {
    bunTest
      .expect(runCursorDispatch('beforeShellExecution', { command: 'printf safe' }))
      .toEqual({ continue: true, permission: 'allow' });
  });

  bunTest.test('turns an unattended ask into a deny', () => {
    bunTest
      .expect(runCursorDispatch('beforeShellExecution', { command: 'sudo echo unsafe' }))
      .toMatchObject({ continue: true, permission: 'deny' });
  });

  bunTest.test('fails closed for an invalid Cursor event hint', () => {
    bunTest
      .expect(runCursorDispatch('not-a-cursor-event', { command: 'printf safe' }))
      .toMatchObject({ continue: true, permission: 'deny' });
  });

  bunTest.test('fails closed when the Cursor event hint is missing', () => {
    bunTest.expect(runCursorDispatch('', {})).toMatchObject({ continue: true, permission: 'deny' });
  });
});

bunTest.describe('Cursor hook installation', () => {
  bunTest.test('migrates a source-file hook to the installed command and current event', () => {
    const [hooks, changed] = addCursorHook(
      [{ command: 'bun /tmp/tripwire.js --cursor-event=preToolUse' }],
      'beforeShellExecution',
    );

    bunTest.expect(changed).toBe(true);
    bunTest.expect(hooks[0]?.command).toBe('tripwire-hook --cursor-event beforeShellExecution');
    bunTest.expect(hooks[0]?.failClosed).toBe(true);
  });

  bunTest.test('recognizes its own bare command and is idempotent', () => {
    const [hooks, changed] = addCursorHook(
      [{ command: 'tripwire-hook --cursor-event preToolUse', failClosed: true }],
      'preToolUse',
    );

    bunTest.expect(changed).toBe(false);
    bunTest.expect(hooks).toHaveLength(1);
  });

  bunTest.test('preserves another command that uses the private flag text', () => {
    const [hooks, changed] = addCursorHook(
      [{ command: 'other-tool --tripwire-hook' }],
      'preToolUse',
    );

    bunTest.expect(changed).toBe(true);
    bunTest.expect(hooks).toContainEqual({ command: 'other-tool --tripwire-hook' });
    bunTest
      .expect(hooks)
      .toContainEqual({ command: 'tripwire-hook --cursor-event preToolUse', failClosed: true });
  });

  bunTest.test('rejects malformed Cursor hook config shapes', () => {
    bunTest.expect(() => parseCursorConfig('{"hooks":[]}')).toThrow('hooks` must be an object');
  });

  bunTest.test(
    'uses the injected home, preserves unknown fields, and is byte-idempotent',
    async () => {
      const homeDirectory = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-cursor-'));
      try {
        const configDirectory = pathModule.join(homeDirectory, '.cursor');
        const configPath = pathModule.join(configDirectory, 'hooks.json');
        await mkdir(configDirectory, { recursive: true });
        await writeFile(
          configPath,
          `${JSON.stringify({
            hooks: {
              customEvent: [{ command: 'custom-hook', sentinel: 'keep-hook' }],
              preToolUse: [
                {
                  command: 'bun /tmp/tripwire.js --cursor-event preToolUse',
                  sentinel: 'keep-tripwire-field',
                },
              ],
            },
            sentinel: 'keep-top-level',
            version: 1,
          })}\n`,
        );

        const first = await installCursor({ homeDirectory });
        bunTest.expect(first.success).toBe(true);
        const firstRaw = await readFile(configPath, 'utf8');
        const config = parseJsonRecord(firstRaw);
        const hooks = recordField(config, 'hooks') ?? {};
        bunTest.expect(config['sentinel']).toBe('keep-top-level');
        bunTest.expect(recordArrayField(hooks, 'customEvent')[0]?.['sentinel']).toBe('keep-hook');
        bunTest
          .expect(recordArrayField(hooks, 'preToolUse')[0]?.['sentinel'])
          .toBe('keep-tripwire-field');

        const second = await installCursor({ homeDirectory });
        bunTest.expect(second.message).toStartWith('Already configured:');
        bunTest.expect(await readFile(configPath, 'utf8')).toBe(firstRaw);
      } finally {
        await rm(homeDirectory, { force: true, recursive: true });
      }
    },
  );
});
