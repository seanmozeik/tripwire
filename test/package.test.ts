import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';

import packageJson from '../package.json' with { type: 'json' };
import platformPackageJson from '../packages/darwin-arm64/package.json' with { type: 'json' };

let root = '';

beforeEach(async () => {
  root = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-package-'));
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

describe('package command contract', () => {
  test('publishes a portable root package with an optional native executable', () => {
    expect(packageJson.bin).toEqual({
      tripwire: './dist/tripwire-cli.js',
      'tripwire-hook': './dist/tripwire-hook.js',
    });
    expect('os' in packageJson).toBe(false);
    expect('cpu' in packageJson).toBe(false);
    expect(packageJson.optionalDependencies).toEqual({
      '@seanmozeik/tripwire-darwin-arm64': packageJson.version,
    });
    expect(packageJson.exports['.']).toEqual({
      default: './dist/index.js',
      import: './dist/index.js',
      types: './dist/types/index.d.ts',
    });
    expect(platformPackageJson.version).toBe(packageJson.version);
    expect(platformPackageJson.os).toEqual(['darwin']);
    expect(platformPackageJson.cpu).toEqual(['arm64']);
    expect(platformPackageJson.exports['.']).toBe('./bin/tripwire');
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
