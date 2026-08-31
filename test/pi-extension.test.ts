import * as bunTest from 'bun:test';
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
  resolveShippedHookCommand,
  tripwirePiDenialReason,
  type TripwireProcessRunner,
} from '../src/pi-extension';
import { parseJsonRecord, recordArrayField, recordField } from './support/json';
import { PiHandlerCollector } from './support/pi';

let root = '';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

bunTest.beforeEach(async () => {
  root = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-pi-'));
});

bunTest.afterEach(async () => {
  delete process.env['TRIPWIRE_BUN'];
  delete process.env['TRIPWIRE_FORCE_PORTABLE'];
  await rm(root, { force: true, recursive: true });
});

bunTest.describe('Tripwire Pi extension', () => {
  bunTest.test(
    'resolves the portable Bun dispatcher through the Pi extension symlink',
    async () => {
      const dist = pathModule.join(root, 'dist');
      const extensions = pathModule.join(root, '.pi', 'agent', 'extensions');
      await mkdir(dist, { recursive: true });
      await mkdir(extensions, { recursive: true });
      const extensionSource = pathModule.join(dist, 'tripwire-pi.js');
      const hook = pathModule.join(dist, 'tripwire.js');
      const installed = pathModule.join(extensions, 'tripwire.js');
      await Promise.all([
        writeFile(extensionSource, 'export default () => {};\n'),
        writeFile(hook, '#!/usr/bin/env bun\n'),
        symlink(extensionSource, installed),
      ]);

      process.env['TRIPWIRE_BUN'] = process.execPath;
      process.env['TRIPWIRE_FORCE_PORTABLE'] = '1';
      bunTest
        .expect(resolveShippedHookCommand(pathToFileURL(installed).href))
        .toEqual({
          arguments: [realpathSync(hook)],
          executable: process.execPath,
          kind: 'portable',
        });
    },
  );

  bunTest.test('understands Tripwire denials and fails closed on invalid output', () => {
    bunTest
      .expect(
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
      )
      .toBe('Use trash instead.');
    bunTest
      .expect(tripwirePiDenialReason({ exitCode: 0, stderr: '', stdout: 'not json' }))
      .toBe('Tripwire returned invalid JSON');
    bunTest
      .expect(tripwirePiDenialReason({ exitCode: 2, stderr: 'hook failed', stdout: '' }))
      .toBe('hook failed');
    bunTest
      .expect(
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
      )
      .toBe('Approval required.');
    bunTest
      .expect(
        tripwirePiDenialReason({
          exitCode: 0,
          stderr: '',
          stdout: JSON.stringify({ continue: true, decision: 'block', reason: 'Secret found.' }),
        }),
      )
      .toBe('Secret found.');
    bunTest
      .expect(tripwirePiDenialReason({ exitCode: 0, stderr: '', stdout: '{}' }))
      .toBe('Tripwire returned an unrecognized response');
  });

  bunTest.test('normalizes Pi and oh-my-pi file inputs for Tripwire rules', () => {
    bunTest
      .expect(
        hookInputs(
          { input: { path: '.env' }, toolCallId: 'read-1', toolName: 'read' },
          'PreToolUse',
          root,
        ),
      )
      .toMatchObject([{ tool_input: { file_path: '.env' }, tool_name: 'read' }]);

    bunTest
      .expect(
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
      )
      .toMatchObject([
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
    bunTest.expect(hashlineInputs).toHaveLength(2);
    bunTest
      .expect(hashlineInputs[1])
      .toMatchObject({ tool_input: { file_path: '.env', new_string: '¶one.ts#abcd\n+change' } });

    const applyPatchInputs = hookInputs(
      {
        input: {
          input: `Apply this patch exactly:

*** Begin Patch
*** Update File: package.json
@@
-  "version": "0.7.0"
+  "version": "0.7.1"
*** Add File: src/added.ts
+export const added = true;
+export const marker = '*** End Patch';
*** Update File: src/old.ts
*** Move to: src/new.ts
@@
-const oldName = true;
+const newName = true;
*** Delete File: .oxlintrc.json
*** End Patch`,
        },
        toolCallId: 'edit-3',
        toolName: 'edit',
      },
      'PreToolUse',
      root,
    );
    bunTest.expect(applyPatchInputs).toHaveLength(5);
    bunTest.expect(applyPatchInputs.map((input) => input['tool_input'])).toEqual([
      {
        file_path: 'package.json',
        new_string: '  "version": "0.7.1"',
        old_string: '  "version": "0.7.0"',
      },
      {
        file_path: 'src/added.ts',
        new_string: "export const added = true;\nexport const marker = '*** End Patch';",
        old_string: '',
      },
      {
        file_path: 'src/old.ts',
        new_string: 'const newName = true;',
        old_string: 'const oldName = true;',
      },
      {
        file_path: 'src/new.ts',
        new_string: 'const newName = true;',
        old_string: 'const oldName = true;',
      },
      { file_path: '.oxlintrc.json', new_string: '', old_string: '' },
    ]);
  });

  bunTest.test('converts Pi text blocks into post-tool secret-scan input', () => {
    bunTest
      .expect(
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
      )
      .toMatchObject([
        { hook_event_name: 'PostToolUse', tool_response: { stderr: '', stdout: 'first\nsecond' } },
      ]);
  });

  bunTest.test('starts one dispatcher process and checks all five edit paths', async () => {
    const collector = new PiHandlerCollector();
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
    createTripwirePiExtension('/unused/tripwire', processRunner)(collector);
    const toolCall = collector.requireToolCall();

    let aborted = false;
    const notifications: string[] = [];
    const result = await toolCall(
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

    bunTest.expect(processCalls).toBe(1);
    bunTest.expect(receivedInput).toBeArrayOfSize(5);
    bunTest.expect(receivedPaths).toEqual(['one.ts', 'two.ts', 'three.ts', 'four.ts', '.env']);
    bunTest.expect(result).toEqual({ block: true, reason: 'Protected path .env' });
    bunTest.expect(aborted).toBe(false);
    bunTest.expect(notifications).toEqual([]);
  });

  bunTest.test('evaluates canonical private batches with one merged response', () => {
    const run = (input: unknown) => {
      const child = Bun.spawnSync([process.execPath, 'src/dispatch.ts', '--tripwire-hook'], {
        env: { ...process.env, HOME: root },
        stdin: new TextEncoder().encode(JSON.stringify(input)),
        stderr: 'pipe',
        stdout: 'pipe',
      });
      bunTest.expect(child.exitCode).toBe(0);
      return parseJsonRecord(child.stdout.toString());
    };
    const event = (filePath: string) => ({
      cwd: root,
      hook_event_name: 'PreToolUse',
      tool_input: { file_path: filePath, new_string: 'new', old_string: 'old' },
      tool_name: 'Edit',
      tool_use_id: `edit-${filePath}`,
    });

    bunTest.expect(run([event('one.ts'), event('two.ts')])).toEqual({ continue: true });
    const denied = run([event('safe.ts'), event('.env')]);
    const hookOutput = recordField(denied, 'hookSpecificOutput');
    bunTest.expect(hookOutput?.['permissionDecision']).toBe('deny');
    bunTest.expect(hookOutput?.['permissionDecisionReason']).toContain('.env');
  });

  bunTest.test('rejects empty, mixed-phase, and mixed-host private batches', () => {
    const run = (input: unknown) => {
      const child = Bun.spawnSync([process.execPath, 'src/dispatch.ts', '--tripwire-hook'], {
        env: { ...process.env, HOME: root },
        stdin: new TextEncoder().encode(JSON.stringify(input)),
        stderr: 'pipe',
        stdout: 'pipe',
      });
      bunTest.expect(child.exitCode).toBe(0);
      return child.stdout.toString();
    };
    const event = {
      cwd: root,
      hook_event_name: 'PreToolUse',
      tool_input: { command: 'printf safe' },
      tool_name: 'Bash',
    };

    bunTest.expect(run([])).toContain('tripwire-batch-error');
    bunTest.expect(run([{}])).toContain('tripwire-batch-error');
    bunTest
      .expect(run([event, { ...event, hook_event_name: 'PostToolUse' }]))
      .toContain('tripwire-batch-error');
    bunTest
      .expect(run([event, { ...event, turn_id: 'codex-turn' }]))
      .toContain('tripwire-batch-error');
  });

  bunTest.test('keeps the native failure response for invalid single-event JSON', () => {
    const child = Bun.spawnSync([process.execPath, 'src/dispatch.ts', '--tripwire-hook'], {
      env: { ...process.env, HOME: root },
      stdin: new TextEncoder().encode('{invalid'),
      stderr: 'pipe',
      stdout: 'pipe',
    });

    bunTest.expect(child.exitCode).toBe(0);
    bunTest.expect(child.stdout.toString()).toBe('{"continue": true}\n');
  });

  bunTest.test('blocks tool calls when the dispatcher cannot run', async () => {
    const collector = new PiHandlerCollector();
    createTripwirePiExtension(pathModule.join(root, 'missing-dispatcher'))(collector);
    const toolCall = collector.requireToolCall();
    collector.requireToolResult();
    let aborted = false;
    let notification = '';
    const result = await toolCall(
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
    bunTest.expect(result?.block).toBe(true);
    bunTest.expect(result?.reason).toContain('Tripwire failed closed');
    bunTest.expect(aborted).toBe(false);
    bunTest.expect(notification).toBe('');
  });
});

bunTest.describe('Pi installation', () => {
  bunTest.test('installs the native extension and removes stale adapter hooks', async () => {
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
    bunTest.expect(result.success).toBe(true);
    const installed = pathModule.join(agentDirectory, 'extensions', 'tripwire.js');
    const installedStatus = await lstat(installed);
    bunTest.expect(installedStatus.isSymbolicLink()).toBe(true);
    bunTest.expect(await readlink(installed)).toBe(extensionSource);
    const settings = parseJsonRecord(
      await readFile(pathModule.join(agentDirectory, 'settings.json'), 'utf8'),
    );
    const hooks = recordField(settings, 'hooks') ?? {};
    const customGroup = recordArrayField(hooks, 'customEvent')[0] ?? {};
    bunTest.expect(recordArrayField(customGroup, 'hooks')[0]?.['command']).toBe('custom-hook');
    bunTest.expect(settings['packages']).toEqual(['pi-example']);
    bunTest.expect(settings['sentinel']).toBe('keep-top-level');

    const settingsPath = pathModule.join(agentDirectory, 'settings.json');
    const firstRaw = await readFile(settingsPath, 'utf8');
    const second = await installPi({ extensionSource, homeDirectory: root });
    bunTest.expect(second.message).toStartWith('Already configured:');
    bunTest.expect(await readFile(settingsPath, 'utf8')).toBe(firstRaw);
    bunTest.expect(await readlink(installed)).toBe(extensionSource);
  });

  bunTest.test('installs the same native extension for oh-my-pi', async () => {
    const extensionSource = pathModule.join(root, 'tripwire-pi.js');
    await writeFile(extensionSource, 'export default () => {};\n');

    const result = await installOhMyPi({ extensionSource, homeDirectory: root });

    bunTest.expect(result.success).toBe(true);
    const installed = pathModule.join(root, '.omp', 'agent', 'extensions', 'tripwire.js');
    const installedStatus = await lstat(installed);
    bunTest.expect(installedStatus.isSymbolicLink()).toBe(true);
    bunTest.expect(await readlink(installed)).toBe(extensionSource);

    const second = await installOhMyPi({ extensionSource, homeDirectory: root });
    bunTest.expect(second.message).toStartWith('Already configured:');
    bunTest.expect(await readlink(installed)).toBe(extensionSource);
  });

  bunTest.test('updates an existing Tripwire extension symlink to the current build', async () => {
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

    bunTest.expect(result.success).toBe(true);
    bunTest.expect(result.message).toStartWith('Updated ');
    bunTest.expect(await readlink(installed)).toBe(newSource);
  });
});
