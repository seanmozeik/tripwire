import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { chmod, copyFile, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';

import packageJson from '../package.json' with { type: 'json' };

let root = '';

beforeEach(async () => {
  root = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-package-'));
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

describe('package command contract', () => {
  test('maps the live hook directly to the native executable', () => {
    expect(packageJson.bin).toEqual({
      tripwire: './scripts/tripwire-cli',
      'tripwire-hook': './dist/tripwire',
    });
    expect(packageJson.os).toEqual(['darwin']);
    expect(packageJson.cpu).toEqual(['arm64']);
  });

  test('the CLI launcher delegates for absolute and no-slash PATH invocation', async () => {
    const binDirectory = pathModule.join(root, 'bin');
    const launcher = pathModule.join(binDirectory, 'tripwire');
    const hook = pathModule.join(binDirectory, 'tripwire-hook');
    const output = pathModule.join(root, 'arguments.txt');
    await mkdir(binDirectory, { recursive: true });
    await copyFile(pathModule.join(import.meta.dir, '..', 'scripts', 'tripwire-cli'), launcher);
    await writeFile(hook, `#!/bin/sh\nprintf '%s\\n' "$@" > "${output}"\n`);
    await Promise.all([chmod(launcher, 0o755), chmod(hook, 0o755)]);

    const result = Bun.spawnSync([launcher, 'test', 'printf safe']);

    expect(result.exitCode).toBe(0);
    expect(await Bun.file(output).text()).toBe('--tripwire-force-cli\ntest\nprintf safe\n');

    const pathResult = Bun.spawnSync(['tripwire', '--version'], {
      env: { ...process.env, PATH: binDirectory },
    });
    expect(pathResult.exitCode).toBe(0);
    expect(await Bun.file(output).text()).toBe('--tripwire-force-cli\n--version\n');
  });

  test('the private flag overrides tripwire-hook argv0 and is hidden from the CLI', async () => {
    const hookPath = pathModule.join(root, 'tripwire-hook');
    await symlink(process.execPath, hookPath);

    const result = Bun.spawnSync(
      [
        hookPath,
        pathModule.join(import.meta.dir, '..', 'src', 'main.ts'),
        '--tripwire-force-cli',
        '--version',
      ],
      { stderr: 'pipe', stdout: 'pipe' },
    );

    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe('');
    expect(result.stdout.toString()).toBe(`${packageJson.version}\n`);
  });
});
