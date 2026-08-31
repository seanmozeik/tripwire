import * as bunTest from 'bun:test';
import { mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import pathModule from 'node:path';

import packageJson from '../package.json' with { type: 'json' };
import platformPackageJson from '../packages/darwin-arm64/package.json' with { type: 'json' };

let root = '';

bunTest.beforeEach(async () => {
  root = await mkdtemp(pathModule.join(tmpdir(), 'tripwire-package-'));
});

bunTest.afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

bunTest.describe('package command contract', () => {
  bunTest.test('publishes a portable root package with an optional native executable', () => {
    bunTest
      .expect(packageJson.bin)
      .toEqual({ tripwire: './dist/tripwire-cli.js', 'tripwire-hook': './dist/tripwire-hook.js' });
    bunTest.expect('os' in packageJson).toBe(false);
    bunTest.expect('cpu' in packageJson).toBe(false);
    bunTest
      .expect(packageJson.optionalDependencies)
      .toEqual({ '@seanmozeik/tripwire-darwin-arm64': packageJson.version });
    bunTest
      .expect(packageJson.exports['.'])
      .toEqual({
        default: './dist/index.js',
        import: './dist/index.js',
        types: './dist/types/index.d.ts',
      });
    bunTest.expect(platformPackageJson.version).toBe(packageJson.version);
    bunTest.expect(platformPackageJson.os).toEqual(['darwin']);
    bunTest.expect(platformPackageJson.cpu).toEqual(['arm64']);
    bunTest.expect(platformPackageJson.exports['.']).toBe('./bin/tripwire');
  });

  bunTest.test(
    'the private flag overrides tripwire-hook argv0 and is hidden from the CLI',
    async () => {
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

      bunTest.expect(result.exitCode).toBe(0);
      bunTest.expect(result.stderr.toString()).toBe('');
      bunTest.expect(result.stdout.toString()).toBe(`${packageJson.version}\n`);
    },
  );
});
