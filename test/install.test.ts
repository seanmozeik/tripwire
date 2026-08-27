import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
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

let homeDirectory = '';

beforeEach(async () => {
  homeDirectory = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-install-'));
});

afterEach(async () => {
  await rm(homeDirectory, { force: true, recursive: true });
});

describe('atomic settings replacement', () => {
  test('keeps the live target and cleans the pending file when publication fails', async () => {
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

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe('forced pre-rename failure');
    expect(await readFile(targetPath, 'utf8')).toBe('original\n');
    expect(await Bun.file(pendingPath).exists()).toBe(false);
  });

  test('preserves the existing target mode', async () => {
    const targetPath = pathModule.join(homeDirectory, 'settings.json');
    await writeFile(targetPath, 'original\n');
    await chmod(targetPath, 0o640);

    await replaceTextAtomically(targetPath, 'replacement\n');

    expect(await readFile(targetPath, 'utf8')).toBe('replacement\n');
    const targetStatus = await stat(targetPath);
    expect(targetStatus.mode & 0o7777).toBe(0o640);
  });

  test('publishes through a relative symlink without replacing the link', async () => {
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
    expect(linkStatus.isSymbolicLink()).toBe(true);
    expect(await readlink(linkedPath)).toBe(relativeTarget);
    expect(await readFile(managedPath, 'utf8')).toBe('replacement\n');
    const managedStatus = await stat(managedPath);
    expect(managedStatus.mode & 0o7777).toBe(0o640);
    expect(await Bun.file(`${managedPath}.${process.pid}.next`).exists()).toBe(false);
  });
});

describe('Claude installation', () => {
  test('preserves unknown fields and is byte-idempotent after the first update', async () => {
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
    expect(first.success).toBe(true);
    const firstRaw = await readFile(configPath, 'utf8');
    const config = JSON.parse(firstRaw) as {
      hooks: {
        PostToolUse: { hooks: { command?: string }[] }[];
        PreToolUse: { hooks: { command?: string; label?: string }[]; label?: string }[];
      };
      theme?: string;
    };
    expect(config.theme).toBe('keep-top-level');
    expect(config.hooks.PreToolUse[0]?.label).toBe('keep-group');
    expect(config.hooks.PreToolUse[0]?.hooks[0]?.label).toBe('keep-hook');
    expect(
      config.hooks.PreToolUse.flatMap((group) => group.hooks).map((hook) => hook.command),
    ).toContain(nativeCommand);
    expect(
      config.hooks.PostToolUse.flatMap((group) => group.hooks).map((hook) => hook.command),
    ).toContain(nativeCommand);

    const second = await installClaude({ homeDirectory, hookCommand: nativeCommand });
    expect(second.message).toStartWith('Already configured:');
    expect(await readFile(configPath, 'utf8')).toBe(firstRaw);
  });
});

describe('Codex installation', () => {
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

  test('prevalidates malformed TOML before writing hooks.json', async () => {
    const [hooksPath, tomlPath] = await createCodexFiles(
      { preserved: 'yes' },
      '[features]\nhooks = = false\n',
    );
    const beforeHooks = await readFile(hooksPath, 'utf8');
    const beforeToml = await readFile(tomlPath, 'utf8');

    const result = await installCodex({ homeDirectory });

    expect(result.success).toBe(false);
    expect(await readFile(hooksPath, 'utf8')).toBe(beforeHooks);
    expect(await readFile(tomlPath, 'utf8')).toBe(beforeToml);
    expect(await Bun.file(`${hooksPath}.${process.pid}.next`).exists()).toBe(false);
    expect(await Bun.file(`${tomlPath}.${process.pid}.next`).exists()).toBe(false);
  });

  test('preserves unknown JSON fields and TOML bytes outside the hook value', async () => {
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

    expect(result.success).toBe(true);
    const hooks = JSON.parse(await readFile(hooksPath, 'utf8')) as {
      hooks: {
        PostToolUse: { hooks: { command?: string }[] }[];
        PreToolUse: { hooks: { command?: string; sentinel?: string }[]; sentinel?: string }[];
      };
      sentinel?: string;
    };
    expect(hooks.sentinel).toBe('keep-top-level');
    expect(hooks.hooks.PreToolUse[0]?.sentinel).toBe('keep-group');
    expect(hooks.hooks.PreToolUse[0]?.hooks[0]?.sentinel).toBe('keep-hook');
    expect(
      hooks.hooks.PreToolUse.flatMap((group) => group.hooks).map((hook) => hook.command),
    ).toContain(nativeCommand);
    expect(
      hooks.hooks.PostToolUse.flatMap((group) => group.hooks).map((hook) => hook.command),
    ).toContain(nativeCommand);
    expect(await readFile(tomlPath, 'utf8')).toBe(originalToml.replace('false #', 'true #'));
  });

  test('repairs a first-file-only update and is byte-idempotent', async () => {
    const originalToml = 'model = "keep"\n\n[notice]\nhide = false\n';
    const [hooksPath, tomlPath] = await createCodexFiles({}, originalToml);
    const first = await installCodex({ homeDirectory });
    expect(first.success).toBe(true);
    const publishedHooks = await readFile(hooksPath, 'utf8');

    // Recreate the documented state after hooks.json was published but config.toml was not.
    await writeFile(tomlPath, originalToml);
    const repaired = await installCodex({ homeDirectory });
    expect(repaired.success).toBe(true);
    expect(await readFile(hooksPath, 'utf8')).toBe(publishedHooks);
    expect(await readFile(tomlPath, 'utf8')).toBe(`${originalToml}[features]\nhooks = true\n`);

    const repairedToml = await readFile(tomlPath, 'utf8');
    const third = await installCodex({ homeDirectory });
    expect(third.message).toStartWith('Already configured:');
    expect(await readFile(hooksPath, 'utf8')).toBe(publishedHooks);
    expect(await readFile(tomlPath, 'utf8')).toBe(repairedToml);
  });
});
