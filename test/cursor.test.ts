import { describe, expect, test } from 'bun:test';

import { normalizeHookInput } from '../src/lib/cursor';
import { addCursorHook, parseCursorConfig } from '../src/lib/install';

const runCursorDispatch = (eventName: string, input: unknown): unknown => {
  const processResult = Bun.spawnSync(['bun', 'src/dispatch.ts', '--cursor-event', eventName], {
    stdin: new TextEncoder().encode(JSON.stringify(input)),
    stdout: 'pipe',
    stderr: 'pipe',
  });
  expect(processResult.exitCode).toBe(0);
  return JSON.parse(processResult.stdout.toString()) as unknown;
};

describe('Cursor hook normalization', () => {
  test('turns beforeShellExecution into a Tripwire Bash pre-tool event', () => {
    const normalized = normalizeHookInput(
      { command: 'rm -rf /', cwd: '/tmp' },
      'beforeShellExecution',
    );

    expect(normalized.host).toEqual({
      kind: 'cursor',
      eventName: 'beforeShellExecution',
      post: false,
    });
    expect(normalized.event).toMatchObject({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
  });

  test('normalizes Cursor Shell tool payloads from generic preToolUse', () => {
    const normalized = normalizeHookInput({
      hook_event_name: 'preToolUse',
      tool_name: 'Shell',
      tool_input: { command: 'printf safe' },
    });

    expect(normalized.event).toMatchObject({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'printf safe' },
    });
  });

  test('infers a top-level generic shell payload when Cursor omits tool metadata', () => {
    const normalized = normalizeHookInput({
      hook_event_name: 'preToolUse',
      command: 'npm --version',
    });

    expect(normalized.event).toMatchObject({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'npm --version' },
    });
  });

  test('maps afterShellExecution output to Tripwire post-tool response', () => {
    const normalized = normalizeHookInput(
      { command: 'printf safe', output: 'safe output' },
      'afterShellExecution',
    );

    expect(normalized.event).toMatchObject({
      hook_event_name: 'PostToolUse',
      tool_name: 'Bash',
      tool_response: { stdout: 'safe output', stderr: '' },
    });
  });

  test('rejects an incomplete known Cursor pre-tool payload', () => {
    expect(() => normalizeHookInput({}, 'beforeShellExecution')).toThrow('missing command');
  });
});

describe('Cursor hook output', () => {
  test('denies a dangerous beforeShellExecution command', () => {
    expect(runCursorDispatch('beforeShellExecution', { command: 'rm -rf /' })).toMatchObject({
      continue: true,
      permission: 'deny',
    });
  });

  test('allows a safe beforeShellExecution command', () => {
    expect(runCursorDispatch('beforeShellExecution', { command: 'printf safe' })).toEqual({
      continue: true,
      permission: 'allow',
    });
  });

  test('turns an unattended ask into a deny', () => {
    expect(
      runCursorDispatch('beforeShellExecution', { command: 'sudo echo unsafe' }),
    ).toMatchObject({ continue: true, permission: 'deny' });
  });

  test('fails closed for an invalid Cursor event hint', () => {
    expect(runCursorDispatch('not-a-cursor-event', { command: 'printf safe' })).toMatchObject({
      continue: true,
      permission: 'deny',
    });
  });

  test('fails closed when the Cursor event hint is missing', () => {
    expect(runCursorDispatch('', {})).toMatchObject({ continue: true, permission: 'deny' });
  });
});

describe('Cursor hook installation', () => {
  test('replaces an existing event hint instead of appending a second one', () => {
    const [hooks, changed] = addCursorHook(
      [{ command: 'bun /tmp/tripwire.js --cursor-event=preToolUse' }],
      'beforeShellExecution',
    );

    expect(changed).toBe(true);
    expect(hooks[0]?.command).toBe('bun /tmp/tripwire.js --cursor-event beforeShellExecution');
    expect(hooks[0]?.failClosed).toBe(true);
  });

  test('recognizes its own bare command and is idempotent', () => {
    const [hooks, changed] = addCursorHook(
      [{ command: 'tripwire-hook --cursor-event preToolUse', failClosed: true }],
      'preToolUse',
    );

    expect(changed).toBe(false);
    expect(hooks).toHaveLength(1);
  });

  test('rejects malformed Cursor hook config shapes', () => {
    expect(() => parseCursorConfig('{"hooks":[]}')).toThrow('hooks` must be an object');
  });
});
