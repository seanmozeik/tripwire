import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { realpathSync } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';
import { pathToFileURL } from 'node:url';

import { installOhMyPi, installPi } from '../src/lib/install';
import {
  createTripwirePiExtension,
  hookInputs,
  resolveShippedHookPath,
  tripwirePiDenialReason,
  type PiExtensionContext,
  type PiToolCallEvent,
  type PiToolResultEvent,
  type TripwirePiExtensionApi,
  type TripwireProcessRunner,
} from '../src/pi-extension';

let root = '';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

beforeEach(async () => {
  root = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-pi-'));
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

describe('Tripwire Pi extension', () => {
  test('resolves the Bun dispatcher through the Pi extension symlink', async () => {
    const dist = pathModule.join(root, 'dist');
    const extensions = pathModule.join(root, '.pi', 'agent', 'extensions');
    await mkdir(dist, { recursive: true });
    await mkdir(extensions, { recursive: true });
    const extensionSource = pathModule.join(dist, 'tripwire-pi.js');
    const hook = pathModule.join(dist, 'tripwire');
    const installed = pathModule.join(extensions, 'tripwire.js');
    await Promise.all([
      writeFile(extensionSource, 'export default () => {};\n'),
      writeFile(hook, '#!/usr/bin/env bun\n'),
      symlink(extensionSource, installed),
    ]);

    expect(resolveShippedHookPath(pathToFileURL(installed).href)).toBe(realpathSync(hook));
  });

  test('understands Tripwire denials and fails closed on invalid output', () => {
    expect(
      tripwirePiDenialReason({
        exitCode: 0,
        stderr: '',
        stdout: JSON.stringify({
          hookSpecificOutput: {
            permissionDecision: 'deny',
            permissionDecisionReason: 'Use trash instead.',
          },
        }),
      }),
    ).toBe('Use trash instead.');
    expect(tripwirePiDenialReason({ exitCode: 0, stderr: '', stdout: 'not json' })).toBe(
      'Tripwire returned invalid JSON',
    );
    expect(tripwirePiDenialReason({ exitCode: 2, stderr: 'hook failed', stdout: '' })).toBe(
      'hook failed',
    );
    expect(
      tripwirePiDenialReason({
        exitCode: 0,
        stderr: '',
        stdout: JSON.stringify({
          hookSpecificOutput: {
            permissionDecision: 'ask',
            permissionDecisionReason: 'Approval required.',
          },
        }),
      }),
    ).toBe('Approval required.');
    expect(
      tripwirePiDenialReason({
        exitCode: 0,
        stderr: '',
        stdout: JSON.stringify({ continue: true, decision: 'block', reason: 'Secret found.' }),
      }),
    ).toBe('Secret found.');
    expect(tripwirePiDenialReason({ exitCode: 0, stderr: '', stdout: '{}' })).toBe(
      'Tripwire returned an unrecognized response',
    );
  });

  test('normalizes Pi and oh-my-pi file inputs for Tripwire rules', () => {
    expect(
      hookInputs(
        { input: { path: '.env' }, toolCallId: 'read-1', toolName: 'read' },
        'PreToolUse',
        root,
      ),
    ).toMatchObject([{ tool_input: { file_path: '.env' }, tool_name: 'read' }]);

    expect(
      hookInputs(
        {
          input: {
            edits: [{ newText: 'const value = 2;', oldText: 'const value = 1;' }],
            path: 'src/value.ts',
          },
          toolCallId: 'edit-1',
          toolName: 'edit',
        },
        'PreToolUse',
        root,
      ),
    ).toMatchObject([
      {
        tool_input: {
          file_path: 'src/value.ts',
          new_string: 'const value = 2;',
          old_string: 'const value = 1;',
        },
      },
    ]);

    const hashlineInputs = hookInputs(
      {
        input: { input: '¶one.ts#abcd\n+change', paths: ['one.ts', '.env'] },
        toolCallId: 'edit-2',
        toolName: 'edit',
      },
      'PreToolUse',
      root,
    );
    expect(hashlineInputs).toHaveLength(2);
    expect(hashlineInputs[1]).toMatchObject({
      tool_input: { file_path: '.env', new_string: '¶one.ts#abcd\n+change' },
    });
  });

  test('converts Pi text blocks into post-tool secret-scan input', () => {
    expect(
      hookInputs(
        {
          content: [
            { text: 'first', type: 'text' },
            { text: 'second', type: 'text' },
          ],
          details: {},
          input: { command: 'printf output' },
          isError: false,
          toolCallId: 'bash-1',
          toolName: 'bash',
        },
        'PostToolUse',
        root,
      ),
    ).toMatchObject([
      { hook_event_name: 'PostToolUse', tool_response: { stderr: '', stdout: 'first\nsecond' } },
    ]);
  });

  test('starts one dispatcher process and checks all five edit paths', async () => {
    let toolCall:
      | ((
          event: PiToolCallEvent,
          context: PiExtensionContext,
        ) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>)
      | undefined;
    let processCalls = 0;
    let receivedInput: unknown;
    const receivedPaths: string[] = [];
    const processRunner: TripwireProcessRunner = (_hookPath, input) => {
      processCalls += 1;
      receivedInput = input;
      const events: readonly unknown[] = Array.isArray(input) ? input : [input];
      const blocked = events.some((event) => {
        if (!isRecord(event)) {
          return false;
        }
        const toolInput = event['tool_input'];
        if (!isRecord(toolInput) || typeof toolInput['file_path'] !== 'string') {
          return false;
        }
        receivedPaths.push(toolInput['file_path']);
        return toolInput['file_path'] === '.env';
      });
      return Promise.resolve({
        exitCode: 0,
        stderr: '',
        stdout: JSON.stringify(
          blocked
            ? {
                hookSpecificOutput: {
                  hookEventName: 'PreToolUse',
                  permissionDecision: 'deny',
                  permissionDecisionReason: 'Protected path .env',
                },
              }
            : { continue: true },
        ),
      });
    };
    const api: TripwirePiExtensionApi = {
      on: (event, handler) => {
        if (event === 'tool_call') {
          toolCall = handler as typeof toolCall;
        }
      },
    };
    createTripwirePiExtension('/unused/tripwire', processRunner)(api);

    let aborted = false;
    const notifications: string[] = [];
    const result = await toolCall?.(
      {
        input: {
          new_string: 'safe replacement',
          old_string: 'old value',
          paths: ['one.ts', 'two.ts', 'three.ts', 'four.ts', '.env'],
        },
        toolCallId: 'batch-edit-1',
        toolName: 'edit',
      },
      {
        abort: () => {
          aborted = true;
        },
        cwd: root,
        ui: {
          notify: (message) => {
            notifications.push(message);
          },
        },
      },
    );

    expect(processCalls).toBe(1);
    expect(receivedInput).toBeArrayOfSize(5);
    expect(receivedPaths).toEqual(['one.ts', 'two.ts', 'three.ts', 'four.ts', '.env']);
    expect(result).toEqual({ block: true, reason: 'Protected path .env' });
    expect(aborted).toBe(false);
    expect(notifications).toEqual([]);
  });

  test('evaluates canonical private batches with one merged response', () => {
    const run = (input: unknown) => {
      const child = Bun.spawnSync([process.execPath, 'src/dispatch.ts', '--tripwire-hook'], {
        env: { ...process.env, HOME: root },
        stdin: new TextEncoder().encode(JSON.stringify(input)),
        stderr: 'pipe',
        stdout: 'pipe',
      });
      expect(child.exitCode).toBe(0);
      return JSON.parse(child.stdout.toString()) as {
        continue?: boolean;
        hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
      };
    };
    const event = (filePath: string) => ({
      cwd: root,
      hook_event_name: 'PreToolUse',
      tool_input: { file_path: filePath, new_string: 'new', old_string: 'old' },
      tool_name: 'Edit',
      tool_use_id: `edit-${filePath}`,
    });

    expect(run([event('one.ts'), event('two.ts')])).toEqual({ continue: true });
    const denied = run([event('safe.ts'), event('.env')]);
    expect(denied.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(denied.hookSpecificOutput?.permissionDecisionReason).toContain('.env');
  });

  test('rejects empty, mixed-phase, and mixed-host private batches', () => {
    const run = (input: unknown) => {
      const child = Bun.spawnSync([process.execPath, 'src/dispatch.ts', '--tripwire-hook'], {
        env: { ...process.env, HOME: root },
        stdin: new TextEncoder().encode(JSON.stringify(input)),
        stderr: 'pipe',
        stdout: 'pipe',
      });
      expect(child.exitCode).toBe(0);
      return child.stdout.toString();
    };
    const event = {
      cwd: root,
      hook_event_name: 'PreToolUse',
      tool_input: { command: 'printf safe' },
      tool_name: 'Bash',
    };

    expect(run([])).toContain('tripwire-batch-error');
    expect(run([{}])).toContain('tripwire-batch-error');
    expect(run([event, { ...event, hook_event_name: 'PostToolUse' }])).toContain(
      'tripwire-batch-error',
    );
    expect(run([event, { ...event, turn_id: 'codex-turn' }])).toContain('tripwire-batch-error');
  });

  test('keeps the native failure response for invalid single-event JSON', () => {
    const child = Bun.spawnSync([process.execPath, 'src/dispatch.ts', '--tripwire-hook'], {
      env: { ...process.env, HOME: root },
      stdin: new TextEncoder().encode('{invalid'),
      stderr: 'pipe',
      stdout: 'pipe',
    });

    expect(child.exitCode).toBe(0);
    expect(child.stdout.toString()).toBe('{"continue": true}\n');
  });

  test('blocks tool calls when the dispatcher cannot run', async () => {
    let toolCall:
      | ((
          event: PiToolCallEvent,
          context: PiExtensionContext,
        ) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>)
      | undefined;
    let toolResult:
      | ((event: PiToolResultEvent, context: PiExtensionContext) => Promise<void>)
      | undefined;
    const api: TripwirePiExtensionApi = {
      on: (event: 'tool_call' | 'tool_result', handler: typeof toolCall | typeof toolResult) => {
        if (event === 'tool_call') {
          toolCall = handler as typeof toolCall;
        } else {
          toolResult = handler as typeof toolResult;
        }
      },
    };
    createTripwirePiExtension(pathModule.join(root, 'missing-dispatcher'))(api);
    expect(toolResult).toBeDefined();
    expect(toolCall).toBeDefined();
    let aborted = false;
    let notification = '';
    const result = await toolCall?.(
      { input: { command: 'git status' }, toolCallId: 'call-1', toolName: 'bash' },
      {
        abort: () => {
          aborted = true;
        },
        cwd: root,
        ui: {
          notify: (message) => {
            notification = message;
          },
        },
      },
    );
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('Tripwire failed closed');
    expect(aborted).toBe(false);
    expect(notification).toBe('');
  });
});

describe('Pi installation', () => {
  test('installs the native extension and removes stale adapter hooks', async () => {
    const agentDirectory = pathModule.join(root, '.pi', 'agent');
    const extensionSource = pathModule.join(root, 'tripwire-pi.js');
    await mkdir(agentDirectory, { recursive: true });
    await Promise.all([
      writeFile(extensionSource, 'export default () => {};\n'),
      writeFile(
        pathModule.join(agentDirectory, 'settings.json'),
        `${JSON.stringify({
          hooks: {
            PostToolUse: [{ hooks: [{ command: 'tripwire-hook', type: 'command' }] }],
            PreToolUse: [{ hooks: [{ command: 'tripwire-hook', type: 'command' }] }],
            customEvent: [{ hooks: [{ command: 'custom-hook', type: 'command' }] }],
          },
          packages: ['pi-example'],
          sentinel: 'keep-top-level',
        })}\n`,
      ),
    ]);
    const result = await installPi({ extensionSource, homeDirectory: root });
    expect(result.success).toBe(true);
    const installed = pathModule.join(agentDirectory, 'extensions', 'tripwire.js');
    const installedStatus = await lstat(installed);
    expect(installedStatus.isSymbolicLink()).toBe(true);
    expect(await readlink(installed)).toBe(extensionSource);
    const settings = JSON.parse(
      await readFile(pathModule.join(agentDirectory, 'settings.json'), 'utf8'),
    ) as {
      hooks?: { customEvent?: { hooks: { command: string }[] }[] };
      packages?: string[];
      sentinel?: string;
    };
    expect(settings.hooks?.customEvent?.[0]?.hooks[0]?.command).toBe('custom-hook');
    expect(settings.packages).toEqual(['pi-example']);
    expect(settings.sentinel).toBe('keep-top-level');

    const settingsPath = pathModule.join(agentDirectory, 'settings.json');
    const firstRaw = await readFile(settingsPath, 'utf8');
    const second = await installPi({ extensionSource, homeDirectory: root });
    expect(second.message).toStartWith('Already configured:');
    expect(await readFile(settingsPath, 'utf8')).toBe(firstRaw);
    expect(await readlink(installed)).toBe(extensionSource);
  });

  test('installs the same native extension for oh-my-pi', async () => {
    const extensionSource = pathModule.join(root, 'tripwire-pi.js');
    await writeFile(extensionSource, 'export default () => {};\n');

    const result = await installOhMyPi({ extensionSource, homeDirectory: root });

    expect(result.success).toBe(true);
    const installed = pathModule.join(root, '.omp', 'agent', 'extensions', 'tripwire.js');
    const installedStatus = await lstat(installed);
    expect(installedStatus.isSymbolicLink()).toBe(true);
    expect(await readlink(installed)).toBe(extensionSource);

    const second = await installOhMyPi({ extensionSource, homeDirectory: root });
    expect(second.message).toStartWith('Already configured:');
    expect(await readlink(installed)).toBe(extensionSource);
  });

  test('updates an existing Tripwire extension symlink to the current build', async () => {
    const oldDist = pathModule.join(root, 'old', 'dist');
    const newDist = pathModule.join(root, 'new', 'dist');
    const extensionDirectory = pathModule.join(root, '.omp', 'agent', 'extensions');
    const oldSource = pathModule.join(oldDist, 'tripwire-pi.js');
    const newSource = pathModule.join(newDist, 'tripwire-pi.js');
    const installed = pathModule.join(extensionDirectory, 'tripwire.js');
    await Promise.all([
      mkdir(oldDist, { recursive: true }),
      mkdir(newDist, { recursive: true }),
      mkdir(extensionDirectory, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(oldSource, 'export default () => {};\n'),
      writeFile(newSource, 'export default () => {};\n'),
      symlink(oldSource, installed),
    ]);

    const result = await installOhMyPi({ extensionSource: newSource, homeDirectory: root });

    expect(result.success).toBe(true);
    expect(result.message).toStartWith('Updated ');
    expect(await readlink(installed)).toBe(newSource);
  });
});
