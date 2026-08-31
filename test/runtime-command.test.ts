import * as bunTest from 'bun:test';
import { chmod, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { resolveTripwireCommand } from '../src/lib/runtime-command';

let root = '';

bunTest.beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'tripwire-runtime-'));
});

bunTest.afterEach(async () => {
  delete process.env['TRIPWIRE_FORCE_PORTABLE'];
  await rm(root, { force: true, recursive: true });
});

bunTest.describe('runtime command resolution', () => {
  bunTest.test('selects the optional native executable on Apple Silicon', async () => {
    const native = path.join(root, 'tripwire');
    await writeFile(native, '#!/bin/sh\n');
    await chmod(native, 0o755);
    const resolvedNative = await realpath(native);

    bunTest
      .expect(
        resolveTripwireCommand({
          architecture: 'arm64',
          moduleUrl: pathToFileURL(path.join(root, 'tripwire-cli.js')),
          nativeResolver: () => native,
          platform: 'darwin',
        }),
      )
      .toEqual({ arguments: [], executable: resolvedNative, kind: 'native' });
  });

  bunTest.test('selects the portable Bun bundle on every other platform', () => {
    const portable = path.join(root, 'tripwire.js');
    bunTest
      .expect(
        resolveTripwireCommand({
          architecture: 'x64',
          bunExecutable: '/usr/local/bin/bun',
          platform: 'linux',
          portableExecutable: portable,
        }),
      )
      .toEqual({ arguments: [portable], executable: '/usr/local/bin/bun', kind: 'portable' });
  });

  bunTest.test('falls back safely when the optional package is unavailable', () => {
    const portable = path.join(root, 'tripwire.js');
    bunTest
      .expect(
        resolveTripwireCommand({
          architecture: 'arm64',
          nativeResolver: () => path.join(root, 'missing'),
          platform: 'darwin',
          portableExecutable: portable,
        }).kind,
      )
      .toBe('portable');
  });

  bunTest.test('supports an explicit portable-path diagnostic override', async () => {
    const native = path.join(root, 'tripwire');
    await writeFile(native, '#!/bin/sh\n');
    await chmod(native, 0o755);
    process.env['TRIPWIRE_FORCE_PORTABLE'] = '1';

    bunTest
      .expect(
        resolveTripwireCommand({
          architecture: 'arm64',
          nativeResolver: () => native,
          platform: 'darwin',
          portableExecutable: path.join(root, 'tripwire.js'),
        }).kind,
      )
      .toBe('portable');
  });
});
