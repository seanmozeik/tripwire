import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { lstat, mkdir, mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';

import { installPi } from '../src/lib/install';
import {
  createTripwirePiExtension,
  tripwirePiDenialReason,
  type PiExtensionContext,
  type PiToolCallEvent,
  type PiToolResultEvent,
  type TripwirePiExtensionApi,
} from '../src/pi-extension';

let root = '';

beforeEach(async () => {
  root = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-pi-'));
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

describe('Tripwire Pi extension', () => {
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

  test('blocks tool calls when the dispatcher cannot run', async () => {
    let toolCall:
      | ((
          event: PiToolCallEvent,
          context: PiExtensionContext,
        ) => Promise<{ readonly block: true; readonly reason: string } | undefined>)
      | undefined;
    let toolResult:
      | ((event: PiToolResultEvent, context: PiExtensionContext) => Promise<void>)
      | undefined;
    const api: TripwirePiExtensionApi = {
      on: ((event: 'tool_call' | 'tool_result', handler: typeof toolCall | typeof toolResult) => {
        if (event === 'tool_call') {
          toolCall = handler as typeof toolCall;
        } else {
          toolResult = handler as typeof toolResult;
        }
      }) as TripwirePiExtensionApi['on'],
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
          },
          packages: ['pi-example'],
        })}\n`,
      ),
    ]);
    const result = await installPi({ extensionSource, homeDirectory: root });
    expect(result.success).toBe(true);
    const installed = pathModule.join(agentDirectory, 'extensions', 'tripwire.js');
    expect((await lstat(installed)).isSymbolicLink()).toBe(true);
    expect(await readlink(installed)).toBe(extensionSource);
    const settings = JSON.parse(
      await readFile(pathModule.join(agentDirectory, 'settings.json'), 'utf8'),
    ) as { hooks?: unknown; packages?: string[] };
    expect(settings.hooks).toBeUndefined();
    expect(settings.packages).toEqual(['pi-example']);
  });
});
