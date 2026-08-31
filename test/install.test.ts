import * as bunTest from 'bun:test';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';

import { installClaude, installCodex, replaceTextAtomically } from '../src/lib/install';
import { parseJsonRecord, recordArrayField, recordField } from './support/json';

let homeDirectory = '';

const hookGroups = (config: Record<string, unknown>, phase: string) =>
  recordArrayField(recordField(config, 'hooks') ?? {}, phase);

const hooksIn = (group: Record<string, unknown>) => recordArrayField(group, 'hooks');

const hookCommands = (groups: readonly Record<string, unknown>[]): readonly unknown[] =>
  groups.flatMap((group) => hooksIn(group)).map((hook) => hook['command']);

bunTest.beforeEach(async () => {
  homeDirectory = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-install-'));
});

bunTest.afterEach(async () => {
  await rm(homeDirectory, { force: true, recursive: true });
});

bunTest.describe('atomic settings replacement', () => {
  bunTest.test(
    'keeps the live target and cleans the pending file when publication fails',
    async () => {
      const targetPath = pathModule.join(homeDirectory, 'settings.json');
      const pendingPath = `${targetPath}.${process.pid}.next`;
      await writeFile(targetPath, 'original\n');

      let failure: unknown;
      try {
        await replaceTextAtomically(targetPath, 'replacement\n', {
          beforeRename: () => {
            throw new Error('forced pre-rename failure');
          },
        });
      } catch (error) {
        failure = error;
      }

      bunTest.expect(failure).toBeInstanceOf(Error);
      if (!(failure instanceof Error)) {
        throw new Error('Expected replaceTextAtomically to throw an Error');
      }
      bunTest.expect(failure.message).toBe('forced pre-rename failure');
      bunTest.expect(await readFile(targetPath, 'utf8')).toBe('original\n');
      bunTest.expect(await Bun.file(pendingPath).exists()).toBe(false);
    },
  );

  bunTest.test('preserves the existing target mode', async () => {
    const targetPath = pathModule.join(homeDirectory, 'settings.json');
    await writeFile(targetPath, 'original\n');
    await chmod(targetPath, 0o640);

    await replaceTextAtomically(targetPath, 'replacement\n');

    bunTest.expect(await readFile(targetPath, 'utf8')).toBe('replacement\n');
    const targetStatus = await stat(targetPath);
    bunTest.expect(targetStatus.mode & 0o7777).toBe(0o640);
  });

  bunTest.test('publishes through a relative symlink without replacing the link', async () => {
    const managedDirectory = pathModule.join(homeDirectory, 'managed');
    const configDirectory = pathModule.join(homeDirectory, '.agent');
    const managedPath = pathModule.join(managedDirectory, 'settings.json');
    const linkedPath = pathModule.join(configDirectory, 'settings.json');
    await Promise.all([
      mkdir(managedDirectory, { recursive: true }),
      mkdir(configDirectory, { recursive: true }),
    ]);
    await writeFile(managedPath, 'original\n');
    await chmod(managedPath, 0o640);
    const relativeTarget = pathModule.relative(configDirectory, managedPath);
    await symlink(relativeTarget, linkedPath);

    await replaceTextAtomically(linkedPath, 'replacement\n');

    const linkStatus = await lstat(linkedPath);
    bunTest.expect(linkStatus.isSymbolicLink()).toBe(true);
    bunTest.expect(await readlink(linkedPath)).toBe(relativeTarget);
    bunTest.expect(await readFile(managedPath, 'utf8')).toBe('replacement\n');
    const managedStatus = await stat(managedPath);
    bunTest.expect(managedStatus.mode & 0o7777).toBe(0o640);
    bunTest.expect(await Bun.file(`${managedPath}.${process.pid}.next`).exists()).toBe(false);
  });
});

bunTest.describe('Claude installation', () => {
  bunTest.test(
    'preserves unknown fields and is byte-idempotent after the first update',
    async () => {
      const nativeCommand = '/opt/tripwire/bin/tripwire --tripwire-hook';
      const configDirectory = pathModule.join(homeDirectory, '.claude');
      const configPath = pathModule.join(configDirectory, 'settings.json');
      await mkdir(configDirectory, { recursive: true });
      await writeFile(
        configPath,
        `${JSON.stringify({
          hooks: {
            PreToolUse: [
              {
                hooks: [{ command: 'other-hook', label: 'keep-hook', type: 'command' }],
                label: 'keep-group',
              },
            ],
          },
          theme: 'keep-top-level',
        })}\n`,
      );

      const first = await installClaude({ homeDirectory, hookCommand: nativeCommand });
      bunTest.expect(first.success).toBe(true);
      const firstRaw = await readFile(configPath, 'utf8');
      const config = parseJsonRecord(firstRaw);
      const preGroups = hookGroups(config, 'PreToolUse');
      const postGroups = hookGroups(config, 'PostToolUse');
      bunTest.expect(config['theme']).toBe('keep-top-level');
      bunTest.expect(preGroups[0]?.['label']).toBe('keep-group');
      bunTest.expect(hooksIn(preGroups[0] ?? {})[0]?.['label']).toBe('keep-hook');
      bunTest.expect(hookCommands(preGroups)).toContain(nativeCommand);
      bunTest.expect(hookCommands(postGroups)).toContain(nativeCommand);

      const second = await installClaude({ homeDirectory, hookCommand: nativeCommand });
      bunTest.expect(second.message).toStartWith('Already configured:');
      bunTest.expect(await readFile(configPath, 'utf8')).toBe(firstRaw);
    },
  );
});

bunTest.describe('Codex installation', () => {
  const createCodexFiles = async (hooks: unknown, toml: string): Promise<[string, string]> => {
    const configDirectory = pathModule.join(homeDirectory, '.codex');
    const hooksPath = pathModule.join(configDirectory, 'hooks.json');
    const tomlPath = pathModule.join(configDirectory, 'config.toml');
    await mkdir(configDirectory, { recursive: true });
    await Promise.all([
      writeFile(hooksPath, `${JSON.stringify(hooks, null, 2)}\n`),
      writeFile(tomlPath, toml),
    ]);
    return [hooksPath, tomlPath];
  };

  bunTest.test('prevalidates malformed TOML before writing hooks.json', async () => {
    const [hooksPath, tomlPath] = await createCodexFiles(
      { preserved: 'yes' },
      '[features]\nhooks = = false\n',
    );
    const beforeHooks = await readFile(hooksPath, 'utf8');
    const beforeToml = await readFile(tomlPath, 'utf8');

    const result = await installCodex({ homeDirectory });

    bunTest.expect(result.success).toBe(false);
    bunTest.expect(await readFile(hooksPath, 'utf8')).toBe(beforeHooks);
    bunTest.expect(await readFile(tomlPath, 'utf8')).toBe(beforeToml);
    bunTest.expect(await Bun.file(`${hooksPath}.${process.pid}.next`).exists()).toBe(false);
    bunTest.expect(await Bun.file(`${tomlPath}.${process.pid}.next`).exists()).toBe(false);
  });

  bunTest.test('preserves unknown JSON fields and TOML bytes outside the hook value', async () => {
    const nativeCommand = '/opt/tripwire/bin/tripwire --tripwire-hook';
    const originalToml =
      '# leading comment\r\n[features] # keep section comment\r\nother = true\r\nhooks = false # keep value comment\r\n\r\n[notice]\r\nhide = false\r\n';
    const [hooksPath, tomlPath] = await createCodexFiles(
      {
        hooks: {
          PreToolUse: [
            {
              hooks: [{ command: 'other-hook', sentinel: 'keep-hook', type: 'command' }],
              sentinel: 'keep-group',
            },
          ],
        },
        sentinel: 'keep-top-level',
      },
      originalToml,
    );

    const result = await installCodex({ homeDirectory, hookCommand: nativeCommand });

    bunTest.expect(result.success).toBe(true);
    const hooks = parseJsonRecord(await readFile(hooksPath, 'utf8'));
    const preGroups = hookGroups(hooks, 'PreToolUse');
    const postGroups = hookGroups(hooks, 'PostToolUse');
    bunTest.expect(hooks['sentinel']).toBe('keep-top-level');
    bunTest.expect(preGroups[0]?.['sentinel']).toBe('keep-group');
    bunTest.expect(hooksIn(preGroups[0] ?? {})[0]?.['sentinel']).toBe('keep-hook');
    bunTest.expect(hookCommands(preGroups)).toContain(nativeCommand);
    bunTest.expect(hookCommands(postGroups)).toContain(nativeCommand);
    bunTest
      .expect(await readFile(tomlPath, 'utf8'))
      .toBe(originalToml.replace('false #', 'true #'));
  });

  bunTest.test('repairs a first-file-only update and is byte-idempotent', async () => {
    const originalToml = 'model = "keep"\n\n[notice]\nhide = false\n';
    const [hooksPath, tomlPath] = await createCodexFiles({}, originalToml);
    const first = await installCodex({ homeDirectory });
    bunTest.expect(first.success).toBe(true);
    const publishedHooks = await readFile(hooksPath, 'utf8');

    // Recreate the documented state after hooks.json was published but config.toml was not.
    await writeFile(tomlPath, originalToml);
    const repaired = await installCodex({ homeDirectory });
    bunTest.expect(repaired.success).toBe(true);
    bunTest.expect(await readFile(hooksPath, 'utf8')).toBe(publishedHooks);
    bunTest
      .expect(await readFile(tomlPath, 'utf8'))
      .toBe(`${originalToml}[features]\nhooks = true\n`);

    const repairedToml = await readFile(tomlPath, 'utf8');
    const third = await installCodex({ homeDirectory });
    bunTest.expect(third.message).toStartWith('Already configured:');
    bunTest.expect(await readFile(hooksPath, 'utf8')).toBe(publishedHooks);
    bunTest.expect(await readFile(tomlPath, 'utf8')).toBe(repairedToml);
  });
});
